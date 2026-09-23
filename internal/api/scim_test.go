package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	scimCore "github.com/supabase-community/scim-go/pkg/core"
	scimProtocol "github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/storage"
)

const (
	scimServiceProviderConfigPath = "/scim/v2/ServiceProviderConfig"
	scimResourceTypesPath         = "/scim/v2/ResourceTypes"
	scimSchemasPath               = "/scim/v2/Schemas"
	scimUsersPath                 = "/scim/v2/Users"
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

		t.Run("Every route is served by the SCIM server", func(t *testing.T) {
			for _, tc := range []struct{ method, path string }{
				{http.MethodGet, scimServiceProviderConfigPath},
				{http.MethodGet, scimResourceTypesPath},
				{http.MethodGet, scimResourceTypesPath + "/User"},
				{http.MethodGet, scimSchemasPath},
				{http.MethodGet, scimSchemasPath + "/" + string(scimCore.SchemaUser)},
				{http.MethodGet, scimUsersPath},
				{http.MethodPost, scimUsersPath},
				{http.MethodGet, scimUsersPath + "/missing"},
				{http.MethodPut, scimUsersPath + "/missing"},
				{http.MethodPatch, scimUsersPath + "/missing"},
				{http.MethodDelete, scimUsersPath + "/missing"},
			} {
				t.Run(tc.method+" "+tc.path, func(t *testing.T) {
					r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(`{}`))
					w := httptest.NewRecorder()

					api.handler.ServeHTTP(w, r)

					require.Equal(t, scimProtocol.MediaType, w.Header().Get("Content-Type"), w.Body.String())
				})
			}
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

			for _, tc := range []struct {
				method, path string
				allow        []string
			}{
				{http.MethodPut, scimUsersPath, []string{http.MethodGet, http.MethodPost}},
				{http.MethodPost, scimUsersPath + "/missing", []string{http.MethodGet, http.MethodPut, http.MethodPatch, http.MethodDelete}},
			} {
				t.Run(tc.method+" "+tc.path, func(t *testing.T) {
					r := httptest.NewRequest(tc.method, tc.path, nil)
					w := httptest.NewRecorder()

					api.handler.ServeHTTP(w, r)

					require.Equal(t, http.StatusMethodNotAllowed, w.Code)
					require.ElementsMatch(t, tc.allow, w.Header().Values("Allow"))
				})
			}
		})
	})
}
