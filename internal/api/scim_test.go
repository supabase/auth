package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api/scim"
	scimCore "github.com/supabase/auth/internal/api/scim/core"
	scimProtocol "github.com/supabase/auth/internal/api/scim/protocol"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/storage"
)

const (
	scimResourceTypesPath         = "/scim/v2/ResourceTypes"
	scimSchemasPath               = "/scim/v2/Schemas"
	scimServiceProviderConfigPath = "/scim/v2/ServiceProviderConfig"
	scimUserResourceTypePath      = "/scim/v2/ResourceTypes/User"
	scimUserSchemaPath            = "/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User"
	scimUsersPath                 = "/scim/v2/Users"
)

var discoveryPaths = []string{
	scimResourceTypesPath,
	scimSchemasPath,
	scimServiceProviderConfigPath,
	scimUserResourceTypePath,
	scimUserSchemaPath,
}

var scimPaths = []string{
	scimServiceProviderConfigPath,
	scimResourceTypesPath,
	scimUserResourceTypePath,
	scimSchemasPath,
	scimUsersPath,
}

func TestSCIM(t *testing.T) {
	t.Run("Disabled by default", func(t *testing.T) {
		api, _, err := setupAPIForTest()
		require.NoError(t, err)

		require.False(t, api.config.Experimental.ScimEnabled)

		for _, path := range scimPaths {
			r := httptest.NewRequest(http.MethodGet, path, nil)
			w := httptest.NewRecorder()

			api.handler.ServeHTTP(w, r)

			require.Equal(t, http.StatusNotFound, w.Code)
			require.Equal(t, "application/json", w.Header().Get("Content-Type"))
			require.JSONEq(t, `{"code":404,"error_code":"feature_disabled","msg":"SCIM server is disabled"}`, w.Body.String())
		}

		t.Run("Unknown endpoints stay hidden while disabled", func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/scim/v2/Unknown", nil)
			w := httptest.NewRecorder()

			api.handler.ServeHTTP(w, r)

			require.Equal(t, http.StatusNotFound, w.Code)
			require.NotContains(t, w.Body.String(), scimProtocol.SchemaError)
		})
	})

	t.Run("Can be enabled", func(t *testing.T) {
		api, _, err := setupAPIForTestWithCallback(func(config *conf.GlobalConfiguration, conn *storage.Connection) {
			if config != nil {
				config.Experimental.ScimEnabled = true
			}
		})
		require.NoError(t, err)

		require.True(t, api.config.Experimental.ScimEnabled)

		t.Run(scimServiceProviderConfigPath, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, scimServiceProviderConfigPath, nil)
			w := httptest.NewRecorder()

			api.handler.ServeHTTP(w, r)

			require.Equal(t, http.StatusOK, w.Code)
			require.Equal(t, scimProtocol.MediaType, w.Header().Get("Content-Type"))
			require.Contains(t, w.Body.String(), string(scimCore.SchemaServiceProviderConfig))
		})

		t.Run(scimResourceTypesPath, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, scimResourceTypesPath, nil)
			w := httptest.NewRecorder()

			api.handler.ServeHTTP(w, r)

			require.Equal(t, http.StatusOK, w.Code)
			require.Equal(t, scimProtocol.MediaType, w.Header().Get("Content-Type"))
			require.Contains(t, w.Body.String(), scimProtocol.SchemaListResponse)
		})

		t.Run(scimResourceTypesPath+" with filter", func(t *testing.T) {
			filter := url.Values{"filter": {`name eq "User"`}}.Encode()
			r := httptest.NewRequest(http.MethodGet, scimResourceTypesPath+"?"+filter, nil)
			w := httptest.NewRecorder()

			api.handler.ServeHTTP(w, r)

			require.Equal(t, http.StatusForbidden, w.Code)
			require.Equal(t, scimProtocol.MediaType, w.Header().Get("Content-Type"))
			require.Contains(t, w.Body.String(), scimProtocol.SchemaError)
		})

		t.Run(scimUserResourceTypePath, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, scimUserResourceTypePath, nil)
			w := httptest.NewRecorder()

			api.handler.ServeHTTP(w, r)

			require.Equal(t, http.StatusOK, w.Code)
			require.Equal(t, scimProtocol.MediaType, w.Header().Get("Content-Type"))
			require.Contains(t, w.Body.String(), string(scimCore.SchemaResourceType))
		})

		t.Run(scimSchemasPath, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, scimSchemasPath, nil)
			w := httptest.NewRecorder()

			api.handler.ServeHTTP(w, r)

			require.Equal(t, http.StatusOK, w.Code)
			require.Equal(t, scimProtocol.MediaType, w.Header().Get("Content-Type"))
			require.Contains(t, w.Body.String(), scimProtocol.SchemaListResponse)
		})

		t.Run(scimSchemasPath+" with filter", func(t *testing.T) {
			filter := url.Values{"filter": {`name eq "User"`}}.Encode()
			r := httptest.NewRequest(http.MethodGet, scimSchemasPath+"?"+filter, nil)
			w := httptest.NewRecorder()

			api.handler.ServeHTTP(w, r)

			require.Equal(t, http.StatusForbidden, w.Code)
			require.Equal(t, scimProtocol.MediaType, w.Header().Get("Content-Type"))
			require.Contains(t, w.Body.String(), scimProtocol.SchemaError)
		})

		t.Run(scimUserSchemaPath, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, scimUserSchemaPath, nil)
			w := httptest.NewRecorder()

			api.handler.ServeHTTP(w, r)

			require.Equal(t, http.StatusOK, w.Code)
			require.Equal(t, scimProtocol.MediaType, w.Header().Get("Content-Type"))
			require.Contains(t, w.Body.String(), string(scimCore.SchemaSchema))
			require.Contains(t, w.Body.String(), string(scimCore.SchemaUser))
		})

		t.Run("/scim/v2/Schemas/urn%3Aietf%3Aparams%3Ascim%3Aschemas%3Acore%3A2.0%3AUser", func(t *testing.T) {
			path := "/scim/v2/Schemas/urn%3Aietf%3Aparams%3Ascim%3Aschemas%3Acore%3A2.0%3AUser"
			r := httptest.NewRequest(http.MethodGet, path, nil)
			w := httptest.NewRecorder()

			api.handler.ServeHTTP(w, r)

			require.Equal(t, http.StatusOK, w.Code)
			require.Equal(t, scimProtocol.MediaType, w.Header().Get("Content-Type"))
			require.Contains(t, w.Body.String(), string(scimCore.SchemaSchema))
		})

		t.Run("Returns a SCIM 404 for an unknown endpoint", func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/scim/v2/Unknown", nil)
			w := httptest.NewRecorder()

			api.handler.ServeHTTP(w, r)

			require.Equal(t, http.StatusNotFound, w.Code)
			require.Equal(t, scimProtocol.MediaType, w.Header().Get("Content-Type"))
			require.Contains(t, w.Body.String(), scimProtocol.SchemaError)
		})

		t.Run("Returns a SCIM 405 for an unsupported method", func(t *testing.T) {
			for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
				for _, path := range discoveryPaths {
					t.Run(method+" "+path, func(t *testing.T) {
						r := httptest.NewRequest(method, path, nil)
						w := httptest.NewRecorder()

						api.handler.ServeHTTP(w, r)

						require.Equal(t, http.StatusMethodNotAllowed, w.Code)
						require.Equal(t, []string{http.MethodGet}, w.Header().Values("Allow"))
					})
				}
			}
		})
	})
}

// newSCIMProvider creates an SSO provider with a SCIM token, returning both.
// Deleting the provider cascades to its tokens and users.
func newSCIMProvider(t *testing.T, conn *storage.Connection) (provider, token string) {
	t.Helper()

	provider = uuid.Must(uuid.NewV4()).String()
	require.NoError(t, conn.RawQuery(
		"INSERT INTO sso_providers (id, resource_id, created_at, updated_at) VALUES (?, ?, now(), now())",
		provider, "scim-e2e-"+provider,
	).Exec())

	t.Cleanup(func() {
		_ = conn.RawQuery("DELETE FROM sso_providers WHERE id = ?", provider).Exec()
	})

	token, digest := scim.NewSCIMToken()
	require.NoError(t, conn.RawQuery(
		"INSERT INTO scim_tokens (sso_provider_id, token_hash) VALUES (?, ?)", provider, digest,
	).Exec())

	return provider, token
}

// TestSCIMUsersAuthentication walks the whole path a SCIM client takes: the
// router, the bearer token, the tenant it resolves to, and the store behind it.
// Nothing else in TestSCIM authenticates, so without this the auth path and the
// tenant boundary are only tested in isolation.
func TestSCIMUsersAuthentication(t *testing.T) {
	var conn *storage.Connection

	api, _, err := setupAPIForTestWithCallback(func(config *conf.GlobalConfiguration, db *storage.Connection) {
		if config != nil {
			config.Experimental.ScimEnabled = true
		}
		if db != nil {
			conn = db
		}
	})
	require.NoError(t, err)
	require.NotNil(t, conn)

	provider, token := newSCIMProvider(t, conn)
	require.NoError(t, conn.RawQuery(
		"INSERT INTO scim_users (sso_provider_id, resource) VALUES (?, ?)",
		provider, `{"userName":"bjensen@example.com"}`,
	).Exec())

	get := func(t *testing.T, authorization string) *httptest.ResponseRecorder {
		t.Helper()

		r := httptest.NewRequest(http.MethodGet, scimUsersPath, nil)
		if authorization != "" {
			r.Header.Set("Authorization", authorization)
		}

		w := httptest.NewRecorder()
		api.handler.ServeHTTP(w, r)
		return w
	}

	t.Run("serves a provider's users to its own token", func(t *testing.T) {
		w := get(t, "Bearer "+token)

		require.Equal(t, http.StatusOK, w.Code)
		require.Equal(t, scimProtocol.MediaType, w.Header().Get("Content-Type"))
		require.Contains(t, w.Body.String(), "bjensen@example.com")
		require.Contains(t, w.Body.String(), `"totalResults":1`)
	})

	t.Run("answers 401 with a challenge when no token is offered", func(t *testing.T) {
		w := get(t, "")

		require.Equal(t, http.StatusUnauthorized, w.Code)
		require.Equal(t, `Bearer realm="SCIM"`, w.Header().Get("WWW-Authenticate"))
		require.Contains(t, w.Body.String(), string(scimProtocol.SchemaError))
	})

	// The header this replaced sat behind requireAdminCredentials, so an admin
	// credential used to be the way in. It is not one any more.
	t.Run("answers 401 to a credential that is not a SCIM token", func(t *testing.T) {
		w := get(t, "Bearer eyJhbGciOiJIUzI1NiJ9.e30.signature")

		require.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("answers 401 once the token is revoked", func(t *testing.T) {
		doomed, revoked := newSCIMProvider(t, conn)
		require.NoError(t, conn.RawQuery(
			"UPDATE scim_tokens SET revoked_at = now() WHERE sso_provider_id = ?", doomed,
		).Exec())

		require.Equal(t, http.StatusUnauthorized, get(t, "Bearer "+revoked).Code)
	})

	t.Run("does not serve one provider's users to another's token", func(t *testing.T) {
		_, other := newSCIMProvider(t, conn)

		w := get(t, "Bearer "+other)

		require.Equal(t, http.StatusOK, w.Code)
		require.Contains(t, w.Body.String(), `"totalResults":0`)
		require.NotContains(t, w.Body.String(), "bjensen@example.com")
	})
}
