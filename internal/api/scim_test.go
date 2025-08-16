package api

import (
    "bytes"
    "encoding/json"
    "fmt"
    "net/url"
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/supabase/auth/internal/api/provider"
    "github.com/stretchr/testify/require"
    "github.com/supabase/auth/internal/models"
    "github.com/supabase/auth/internal/conf"
    "github.com/supabase/auth/internal/storage"
    "github.com/gofrs/uuid"
)

func setupSCIMAPIForTest(t *testing.T) *API {
    t.Helper()
    api, cfg, err := setupAPIForTestWithCallback(func(c *conf.GlobalConfiguration, _ *storage.Connection) {
        if c != nil {
            c.SCIM.Enabled = true
            c.SCIM.Tokens = []string{"testtoken"}
            if c.API.ExternalURL == "" {
                c.API.ExternalURL = "http://localhost"
            }
            // point DB to test env credentials
            c.DB.URL = "postgres://supabase_auth_admin:root@localhost:5432/postgres"
        }
    })
    require.NoError(t, err)
    t.Cleanup(func() { _ = api.db.Close() })
    // Ensure DB clean
    require.NoError(t, models.TruncateAll(api.db))
    _ = cfg
    return api
}

func TestSCIM_ServiceProviderConfig(t *testing.T) {
    api := setupSCIMAPIForTest(t)

    req := httptest.NewRequest(http.MethodGet, "/scim/v2/ServiceProviderConfig", nil)
    req.Header.Set("Authorization", "Bearer testtoken")
    w := httptest.NewRecorder()
    api.handler.ServeHTTP(w, req)

    require.Equal(t, http.StatusOK, w.Code)

    var body map[string]any
    require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
    require.Contains(t, body["schemas"], "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig")
}

func TestSCIM_UsersLifecycle(t *testing.T) {
    api := setupSCIMAPIForTest(t)

    // Create user
    create := map[string]any{
        "userName":    "scim.user@example.com",
        "displayName": "SCIM User",
        "name": map[string]any{
            "givenName":  "SCIM",
            "familyName": "User",
        },
        "externalId": "ext-123",
    }
    var buf bytes.Buffer
    require.NoError(t, json.NewEncoder(&buf).Encode(create))
    req := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", &buf)
    req.Header.Set("Authorization", "Bearer testtoken")
    w := httptest.NewRecorder()
    api.handler.ServeHTTP(w, req)
    require.Equal(t, http.StatusCreated, w.Code)

    var created map[string]any
    require.NoError(t, json.NewDecoder(w.Body).Decode(&created))
    id := created["id"].(string)
    require.NotEmpty(t, id)

    // Get user and assert active=true
    req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/scim/v2/Users/%s", id), nil)
    req.Header.Set("Authorization", "Bearer testtoken")
    w = httptest.NewRecorder()
    api.handler.ServeHTTP(w, req)
    require.Equal(t, http.StatusOK, w.Code)
    var got map[string]any
    require.NoError(t, json.NewDecoder(w.Body).Decode(&got))
    require.Equal(t, true, got["active"])

    // Patch deactivate (active=false)
    patch := map[string]any{
        "Operations": []any{
            map[string]any{
                "op":   "replace",
                "path": "active",
                "value": false,
            },
        },
    }
    buf.Reset()
    require.NoError(t, json.NewEncoder(&buf).Encode(patch))
    req = httptest.NewRequest(http.MethodPatch, fmt.Sprintf("/scim/v2/Users/%s", id), &buf)
    req.Header.Set("Authorization", "Bearer testtoken")
    w = httptest.NewRecorder()
    api.handler.ServeHTTP(w, req)
    require.Equal(t, http.StatusOK, w.Code)
    var patched map[string]any
    require.NoError(t, json.NewDecoder(w.Body).Decode(&patched))
    require.Equal(t, false, patched["active"]) // now disabled

    // Delete (ban / soft deprovision)
    req = httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/scim/v2/Users/%s", id), nil)
    req.Header.Set("Authorization", "Bearer testtoken")
    w = httptest.NewRecorder()
    api.handler.ServeHTTP(w, req)
    require.Equal(t, http.StatusNoContent, w.Code)

    // Verify in DB: user still exists, not hard-deleted, banned
    uid := uuid.FromStringOrNil(id)
    u, err := models.FindUserByID(api.db, uid)
    require.NoError(t, err)
    require.Nil(t, u.DeletedAt)
    require.True(t, u.IsBanned())

    // GET should still return the user with active=false (soft state)
    req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/scim/v2/Users/%s", id), nil)
    req.Header.Set("Authorization", "Bearer testtoken")
    w = httptest.NewRecorder()
    api.handler.ServeHTTP(w, req)
    require.Equal(t, http.StatusOK, w.Code)
    var afterDel map[string]any
    require.NoError(t, json.NewDecoder(w.Body).Decode(&afterDel))
    require.Equal(t, false, afterDel["active"]) // stays disabled
}

func TestSCIM_AuthRequired(t *testing.T) {
    api := setupSCIMAPIForTest(t)
    req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
    w := httptest.NewRecorder()
    api.handler.ServeHTTP(w, req)
    require.Equal(t, http.StatusForbidden, w.Code)
}

func TestSCIM_SchemasAndResourceTypes(t *testing.T) {
    api := setupSCIMAPIForTest(t)

    // Schemas
    req := httptest.NewRequest(http.MethodGet, "/scim/v2/Schemas", nil)
    req.Header.Set("Authorization", "Bearer testtoken")
    w := httptest.NewRecorder()
    api.handler.ServeHTTP(w, req)
    require.Equal(t, http.StatusOK, w.Code)

    // ResourceTypes
    req = httptest.NewRequest(http.MethodGet, "/scim/v2/ResourceTypes", nil)
    req.Header.Set("Authorization", "Bearer testtoken")
    w = httptest.NewRecorder()
    api.handler.ServeHTTP(w, req)
    require.Equal(t, http.StatusOK, w.Code)
}

func TestSCIM_UsersPagination(t *testing.T) {
    api := setupSCIMAPIForTest(t)

    createUser := func(email string) {
        body := map[string]any{
            "userName": email,
        }
        var buf bytes.Buffer
        _ = json.NewEncoder(&buf).Encode(body)
        req := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", &buf)
        req.Header.Set("Authorization", "Bearer testtoken")
        w := httptest.NewRecorder()
        api.handler.ServeHTTP(w, req)
        require.Equal(t, http.StatusCreated, w.Code)
    }
    createUser("a@example.com")
    createUser("b@example.com")

    req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users?startIndex=1&count=1", nil)
    req.Header.Set("Authorization", "Bearer testtoken")
    w := httptest.NewRecorder()
    api.handler.ServeHTTP(w, req)
    require.Equal(t, http.StatusOK, w.Code)

    var list map[string]any
    _ = json.NewDecoder(w.Body).Decode(&list)
    require.Equal(t, float64(1), list["itemsPerPage"]) // JSON numbers decode to float64
}

func TestSCIM_BasicAuth(t *testing.T) {
    api, _, err := setupAPIForTestWithCallback(func(c *conf.GlobalConfiguration, _ *storage.Connection) {
        if c != nil {
            c.SCIM.Enabled = true
            c.SCIM.Tokens = nil
            c.SCIM.BasicUser = "u"
            c.SCIM.BasicPassword = "p"
            if c.API.ExternalURL == "" { c.API.ExternalURL = "http://localhost" }
            c.DB.URL = "postgres://supabase_auth_admin:root@localhost:5432/postgres"
        }
    })
    require.NoError(t, err)
    t.Cleanup(func() { _ = api.db.Close() })
    require.NoError(t, models.TruncateAll(api.db))

    var buf bytes.Buffer
    _ = json.NewEncoder(&buf).Encode(map[string]any{"userName":"c@example.com"})
    req := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", &buf)
    req.SetBasicAuth("u","p")
    w := httptest.NewRecorder()
    api.handler.ServeHTTP(w, req)
    require.Equal(t, http.StatusCreated, w.Code)
}



// Sets up API with SCIM enabled and a fixed DefaultAudience.
func setupSCIMSecurityAPI(t *testing.T) *API {
    t.Helper()
    api, _, err := setupAPIForTestWithCallback(func(c *conf.GlobalConfiguration, _ *storage.Connection) {
        if c != nil {
            c.SCIM.Enabled = true
            c.SCIM.Tokens = []string{"secr"}
            c.SCIM.DefaultAudience = "tenantA"
            if c.API.ExternalURL == "" { c.API.ExternalURL = "http://localhost" }
            c.DB.URL = "postgres://supabase_auth_admin:root@localhost:5432/postgres"
        }
    })
    require.NoError(t, err)
    t.Cleanup(func() { _ = api.db.Close() })
    require.NoError(t, models.TruncateAll(api.db))
    return api
}

// Ensure listing via SCIM does not return users belonging to another audience.
func TestSCIM_ListDoesNotLeakOtherAudience(t *testing.T) {
    api := setupSCIMSecurityAPI(t)

    // Create a user in tenantA via SCIM
    var buf bytes.Buffer
    _ = json.NewEncoder(&buf).Encode(map[string]any{"userName":"a@example.com"})
    req := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", &buf)
    req.Header.Set("Authorization", "Bearer secr")
    w := httptest.NewRecorder()
    api.handler.ServeHTTP(w, req)
    require.Equal(t, http.StatusCreated, w.Code)

    // Create a user in another audience (tenantB) directly in DB
    other, err := models.NewUser("", "b@example.com", "", "tenantB", nil)
    require.NoError(t, err)
    require.NoError(t, api.db.Create(other))

    // List via SCIM should only include tenantA user
    req = httptest.NewRequest(http.MethodGet, "/scim/v2/Users?startIndex=1&count=50", nil)
    req.Header.Set("Authorization", "Bearer secr")
    w = httptest.NewRecorder()
    api.handler.ServeHTTP(w, req)
    require.Equal(t, http.StatusOK, w.Code)

    var list map[string]any
    _ = json.NewDecoder(w.Body).Decode(&list)
    resources := list["Resources"].([]any)
    require.Len(t, resources, 1)
}

// Ensure filters cannot fetch a user from another audience.
func TestSCIM_FilterOtherAudienceNoResults(t *testing.T) {
    api := setupSCIMSecurityAPI(t)

    // Create user in other audience directly
    other, err := models.NewUser("", "cross@example.com", "", "tenantB", nil)
    require.NoError(t, err)
    require.NoError(t, api.db.Create(other))

    // Filter by userName eq other email should return 0 for tenantA-scoped SCIM
    req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users?filter="+url.QueryEscape("userName eq \"cross@example.com\""), nil)
    req.Header.Set("Authorization", "Bearer secr")
    w := httptest.NewRecorder()
    api.handler.ServeHTTP(w, req)
    require.Equal(t, http.StatusOK, w.Code)

    var list map[string]any
    _ = json.NewDecoder(w.Body).Decode(&list)
    require.Equal(t, float64(0), list["totalResults"]) // JSON numbers decode to float64
}

// Ensure request headers cannot force audience switching during SCIM operations.
func TestSCIM_HeaderAudIgnored(t *testing.T) {
    api := setupSCIMSecurityAPI(t)

    var buf bytes.Buffer
    _ = json.NewEncoder(&buf).Encode(map[string]any{"userName":"hdr@example.com"})
    req := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", &buf)
    req.Header.Set("Authorization", "Bearer secr")
    req.Header.Set(audHeaderName, "tenantB")
    w := httptest.NewRecorder()
    api.handler.ServeHTTP(w, req)
    require.Equal(t, http.StatusCreated, w.Code)

    // Confirm the created user belongs to tenantA (DefaultAudience), not tenantB
    var created map[string]any
    _ = json.NewDecoder(w.Body).Decode(&created)
    id := created["id"].(string)
    uid := uuid.FromStringOrNil(id)
    u, err := models.FindUserByID(api.db, uid)
    require.NoError(t, err)
    require.Equal(t, "tenantA", u.Aud)
}

// This test verifies that a SCIM-provisioned user (non-SSO) remains separate from an SSO user
// created during a SAML flow for the same email, and that deprovisioning via SCIM does not ban the SSO user.
func TestSCIMSAML_UserSeparationAndDeprovision(t *testing.T) {
    api, _, err := setupAPIForTestWithCallback(func(c *conf.GlobalConfiguration, _ *storage.Connection) {
        if c != nil {
            c.SCIM.Enabled = true
            c.SCIM.Tokens = []string{"tok"}
            if c.API.ExternalURL == "" { c.API.ExternalURL = "http://localhost" }
            c.DB.URL = "postgres://supabase_auth_admin:root@localhost:5432/postgres"
        }
    })
    require.NoError(t, err)
    t.Cleanup(func() { _ = api.db.Close() })
    require.NoError(t, models.TruncateAll(api.db))

    // 1) Provision user via SCIM
    email := "samlscim@example.com"
    body := map[string]any{"userName": email, "displayName": "SCIM+SAML"}
    var buf bytes.Buffer
    require.NoError(t, json.NewEncoder(&buf).Encode(body))
    req := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", &buf)
    req.Header.Set("Authorization", "Bearer tok")
    w := httptest.NewRecorder()
    api.handler.ServeHTTP(w, req)
    require.Equal(t, http.StatusCreated, w.Code)

    var created map[string]any
    require.NoError(t, json.NewDecoder(w.Body).Decode(&created))
    scimID := created["id"].(string)
    require.NotEmpty(t, scimID)

    // 2) Simulate SAML login with same email -> should create separate SSO user
    ssoProviderID := uuid.Must(uuid.NewV4()).String()
    upd := provider.UserProvidedData{}
    upd.Emails = append(upd.Emails, provider.Email{Email: email, Verified: true, Primary: true})
    claims := &provider.Claims{Subject: uuid.Must(uuid.NewV4()).String(), Issuer: "entity-id", Email: email, EmailVerified: true}
    upd.Metadata = claims

    // Use a dummy request with correct audience context
    sreq := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)

    // Run in a transaction to mimic SAML ACS behavior
    err = api.db.Transaction(func(tx *storage.Connection) error {
        // providerType must be in sso:<provider_id> form to scope linking domain
        _, terr := api.createAccountFromExternalIdentity(tx, sreq, &upd, "sso:"+ssoProviderID)
        return terr
    })
    require.NoError(t, err)

    // 3) Verify there are two users with same email: one non-SSO (SCIM), one SSO
    users, err := models.FindUsersInAudience(api.db, api.config.JWT.Aud, nil, nil, "")
    require.NoError(t, err)
    var nonSSO, sso *models.User
    for _, u := range users {
        if u.GetEmail() == email {
            if u.IsSSOUser {
                sso = u
            } else {
                nonSSO = u
            }
        }
    }
    require.NotNil(t, nonSSO)
    require.NotNil(t, sso)
    require.Equal(t, nonSSO.ID.String(), scimID)
    require.False(t, nonSSO.IsSSOUser)
    require.True(t, sso.IsSSOUser)

    // 4) Deprovision SCIM user (DELETE via SCIM) -> only SCIM user should be banned, SSO user stays active
    req = httptest.NewRequest(http.MethodDelete, "/scim/v2/Users/"+nonSSO.ID.String(), nil)
    req.Header.Set("Authorization", "Bearer tok")
    w = httptest.NewRecorder()
    api.handler.ServeHTTP(w, req)
    require.Equal(t, http.StatusNoContent, w.Code)

    // Reload both users
    nonSSO, err = models.FindUserByID(api.db, nonSSO.ID)
    require.NoError(t, err)
    sso, err = models.FindUserByID(api.db, sso.ID)
    require.NoError(t, err)

    require.True(t, nonSSO.IsBanned())
    require.False(t, sso.IsBanned())
}

