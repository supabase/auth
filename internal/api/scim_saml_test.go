package api

import (
    "bytes"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/gofrs/uuid"
    "github.com/stretchr/testify/require"
    "github.com/supabase/auth/internal/api/provider"
    "github.com/supabase/auth/internal/conf"
    "github.com/supabase/auth/internal/models"
    "github.com/supabase/auth/internal/storage"
)

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


