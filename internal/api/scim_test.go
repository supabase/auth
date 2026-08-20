package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	scimCore "github.com/supabase/auth/internal/api/scim/core"
	scimProtocol "github.com/supabase/auth/internal/api/scim/protocol"
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

		for _, tc := range []struct {
			path   string
			schema string
		}{
			{scimResourceTypesPath + "/User", string(scimCore.SchemaResourceType)},
			{scimSchemasPath + "/" + string(scimCore.SchemaUser), string(scimCore.SchemaSchema)},
			// A URN's colons are legal to percent-encode in a path segment, and
			// some clients do, so both spellings must reach the same schema.
			{scimSchemasPath + "/" + strings.ReplaceAll(string(scimCore.SchemaUser), ":", "%3A"), string(scimCore.SchemaSchema)},
		} {
			t.Run(tc.path, func(t *testing.T) {
				r := httptest.NewRequest(http.MethodGet, tc.path, nil)
				w := httptest.NewRecorder()

				api.handler.ServeHTTP(w, r)

				require.Equal(t, http.StatusOK, w.Code)
				require.Equal(t, scimProtocol.MediaType, w.Header().Get("Content-Type"))
				require.Contains(t, w.Body.String(), tc.schema)
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
