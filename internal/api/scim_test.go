package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	scimCore "github.com/supabase/auth/internal/api/scim/core"
	scimProtocol "github.com/supabase/auth/internal/api/scim/protocol"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

const (
	scimServiceProviderConfigPath = "/scim/v2/ServiceProviderConfig"
	scimResourceTypesPath         = "/scim/v2/ResourceTypes"
	scimSchemasPath               = "/scim/v2/Schemas"
)

var scimPaths = []string{
	scimServiceProviderConfigPath,
	scimResourceTypesPath,
	scimSchemasPath,
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
			require.Contains(t, w.Body.String(), scimCore.SchemaServiceProviderConfig)
		})

		for _, path := range []string{scimResourceTypesPath, scimSchemasPath} {
			t.Run(path, func(t *testing.T) {
				r := httptest.NewRequest(http.MethodGet, path, nil)
				w := httptest.NewRecorder()

				api.handler.ServeHTTP(w, r)

				require.Equal(t, http.StatusOK, w.Code)
				require.Equal(t, scimProtocol.MediaType, w.Header().Get("Content-Type"))
				require.Contains(t, w.Body.String(), scimProtocol.SchemaListResponse)
			})

			t.Run(path+" rejects filter query parameter", func(t *testing.T) {
				filter := url.Values{"filter": {`name eq "User"`}}.Encode()
				r := httptest.NewRequest(http.MethodGet, path+"?"+filter, nil)
				w := httptest.NewRecorder()

				api.handler.ServeHTTP(w, r)

				require.Equal(t, http.StatusForbidden, w.Code)
				require.Equal(t, scimProtocol.MediaType, w.Header().Get("Content-Type"))
				require.Contains(t, w.Body.String(), scimProtocol.SchemaError)
			})
		}

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
				for _, path := range scimPaths {
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

type scimTenant struct {
	provider *models.SSOProvider
	user     *models.User
	token    string
}

func seedSCIMTenant(t *testing.T, conn *storage.Connection, token, email string) *scimTenant {
	t.Helper()

	id := uuid.Must(uuid.NewV4()).String()
	provider := &models.SSOProvider{
		SAMLProvider: models.SAMLProvider{
			EntityID:    "https://example.com/saml/metadata/" + id,
			MetadataXML: "<example />",
		},
		SSODomains: []models.SSODomain{
			{Domain: id + ".local"},
		},
	}
	provider.UpdateSCIMToken(token)
	require.NoError(t, conn.Eager().Create(provider))

	user, err := models.NewUser("", email, "", "authenticated", nil)
	require.NoError(t, err)
	user.IsSSOUser = true
	require.NoError(t, conn.Create(user))

	identity, err := models.NewIdentity(user, "sso:"+provider.ID.String(), map[string]interface{}{
		"sub":   user.ID.String(),
		"email": email,
	})
	require.NoError(t, err)
	require.NoError(t, conn.Create(identity))

	return &scimTenant{provider: provider, user: user, token: token}
}

func TestSCIMUsers(t *testing.T) {
	var a, b *scimTenant
	var conn *storage.Connection

	api, config, err := setupAPIForTestWithCallback(func(cfg *conf.GlobalConfiguration, c *storage.Connection) {
		if cfg != nil {
			cfg.Experimental.ScimEnabled = true
			return
		}
		conn = c
		require.NoError(t, models.TruncateAll(c))
		a = seedSCIMTenant(t, c, "scim_token_a", "a@example.com")
		b = seedSCIMTenant(t, c, "scim_token_b", "b@example.com")
	})
	require.NoError(t, err)

	get := func(id, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/scim/v2/Users/"+id, nil)
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		api.handler.ServeHTTP(w, r)
		return w
	}

	t.Run("returns the user that belongs to the token's provider", func(t *testing.T) {
		w := get(a.user.ID.String(), a.token)

		require.Equal(t, http.StatusOK, w.Code)
		require.Equal(t, scimProtocol.MediaType, w.Header().Get("Content-Type"))
		require.JSONEq(t, fmt.Sprintf(`{
			"schemas": [%q],
			"id": %q,
			"userName": "a@example.com",
			"emails": [{"value": "a@example.com", "primary": true}],
			"meta": {
				"resourceType": "User",
				"created": %q,
				"lastModified": %q,
				"location": "%s/scim/v2/Users/%s"
			}
		}`,
			scimCore.SchemaUser,
			a.user.ID,
			a.user.CreatedAt.UTC().Format(time.RFC3339Nano),
			a.user.UpdatedAt.UTC().Format(time.RFC3339Nano),
			config.API.ExternalURL, a.user.ID,
		), w.Body.String())
	})

	t.Run("scopes each provider to its own users", func(t *testing.T) {
		require.Equal(t, http.StatusOK, get(b.user.ID.String(), b.token).Code)
	})

	t.Run("hides a user belonging to another provider", func(t *testing.T) {
		w := get(b.user.ID.String(), a.token)

		require.Equal(t, http.StatusNotFound, w.Code)
		require.Equal(t, scimProtocol.MediaType, w.Header().Get("Content-Type"))
		require.Contains(t, w.Body.String(), scimProtocol.SchemaError)
	})

	t.Run("returns the same 404 for an unknown id", func(t *testing.T) {
		unknown := get(uuid.Must(uuid.NewV4()).String(), a.token)
		other := get(b.user.ID.String(), a.token)

		require.Equal(t, http.StatusNotFound, unknown.Code)
		require.Equal(t, other.Body.String(), unknown.Body.String())
	})

	t.Run("returns 404 for a malformed id", func(t *testing.T) {
		w := get("not-a-uuid", a.token)

		require.Equal(t, http.StatusNotFound, w.Code)
		require.Equal(t, scimProtocol.MediaType, w.Header().Get("Content-Type"))
	})

	t.Run("requires a bearer token", func(t *testing.T) {
		w := get(a.user.ID.String(), "")

		require.Equal(t, http.StatusUnauthorized, w.Code)
		require.Equal(t, scimProtocol.MediaType, w.Header().Get("Content-Type"))
		require.Equal(t, "Bearer", w.Header().Get("WWW-Authenticate"))
		require.Contains(t, w.Body.String(), scimProtocol.SchemaError)
	})

	t.Run("rejects an unknown token", func(t *testing.T) {
		w := get(a.user.ID.String(), "scim_nope")

		require.Equal(t, http.StatusUnauthorized, w.Code)
		require.Equal(t, "Bearer", w.Header().Get("WWW-Authenticate"))
	})

	t.Run("rejects a disabled provider", func(t *testing.T) {
		disabled := true
		b.provider.Disabled = &disabled
		require.NoError(t, conn.Update(b.provider))
		defer func() {
			b.provider.Disabled = nil
			require.NoError(t, conn.Update(b.provider))
		}()

		w := get(b.user.ID.String(), b.token)

		require.Equal(t, http.StatusForbidden, w.Code)
		require.Equal(t, scimProtocol.MediaType, w.Header().Get("Content-Type"))
	})

	t.Run("stays hidden when the feature flag is off", func(t *testing.T) {
		disabled, _, err := setupAPIForTest()
		require.NoError(t, err)

		r := httptest.NewRequest(http.MethodGet, "/scim/v2/Users/"+a.user.ID.String(), nil)
		r.Header.Set("Authorization", "Bearer "+a.token)
		w := httptest.NewRecorder()
		disabled.handler.ServeHTTP(w, r)

		require.Equal(t, http.StatusNotFound, w.Code)
		require.Equal(t, "application/json", w.Header().Get("Content-Type"))
		require.NotContains(t, w.Body.String(), scimProtocol.SchemaError)
	})
}

func TestSCIMInfrastructureFailure(t *testing.T) {
	var tenant *scimTenant
	var conn *storage.Connection

	api, _, err := setupAPIForTestWithCallback(func(cfg *conf.GlobalConfiguration, c *storage.Connection) {
		if cfg != nil {
			cfg.Experimental.ScimEnabled = true
			return
		}
		conn = c
		require.NoError(t, models.TruncateAll(c))
		tenant = seedSCIMTenant(t, c, "scim_token_unreachable", "unreachable@example.com")
	})
	require.NoError(t, err)

	rename := func(t *testing.T, from, to string) {
		t.Helper()
		require.NoError(t, conn.RawQuery("alter table "+from+" rename to "+to).Exec())
	}

	// Each table stands in for a database that fails one of the two queries a
	// SCIM request makes, for a reason other than the row being absent.
	for _, table := range []string{"sso_providers", "users"} {
		t.Run("answers in the SCIM error form when "+table+" cannot be queried", func(t *testing.T) {
			rename(t, table, table+"_renamed")
			defer rename(t, table+"_renamed", table)

			r := httptest.NewRequest(http.MethodGet, "/scim/v2/Users/"+tenant.user.ID.String(), nil)
			r.Header.Set("Authorization", "Bearer "+tenant.token)
			w := httptest.NewRecorder()
			api.handler.ServeHTTP(w, r)

			require.Equal(t, http.StatusInternalServerError, w.Code)
			require.Equal(t, scimProtocol.MediaType, w.Header().Get("Content-Type"))
			require.JSONEq(t, `{
				"schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
				"detail": "Unexpected failure, please check server logs for more information",
				"status": "500"
			}`, w.Body.String())
		})
	}
}
