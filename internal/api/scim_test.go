package api

import (
    "bytes"
    "encoding/json"
    "fmt"
    "net/http"
    "net/http/httptest"
    "testing"

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


