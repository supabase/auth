package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api/scim/fixtures"
	"github.com/supabase/auth/internal/api/scim/protocol"
)

func TestSCIM(t *testing.T) {
	scimRoutes := []struct {
		path string
		body string
	}{
		{"/scim/v2/ResourceTypes", fixtures.EmptyListResponse},
		{"/scim/v2/Schemas", fixtures.EmptyListResponse},
		{"/scim/v2/ServiceProviderConfig", fixtures.ServiceProviderConfig},
	}

	t.Run("Disabled by default", func(t *testing.T) {
		api, _, err := setupAPIForTest()
		require.NoError(t, err)
		require.False(t, api.config.Experimental.ScimEnabled)

		for _, route := range scimRoutes {
			t.Run(route.path, func(t *testing.T) {
				r := httptest.NewRequest(http.MethodGet, route.path, nil)
				w := httptest.NewRecorder()

				api.handler.ServeHTTP(w, r)

				require.Equal(t, http.StatusNotFound, w.Code)
				require.NotContains(t, w.Body.String(), protocol.SchemaError)
			})
		}
	})

	t.Run("Mounted when enabled", func(t *testing.T) {
		api, config, err := setupAPIForTest()
		require.NoError(t, err)
		require.NotNil(t, api)
		require.NotNil(t, config)
		config.Experimental.ScimEnabled = true

		for _, route := range scimRoutes {
			t.Run(route.path, func(t *testing.T) {
				r := httptest.NewRequest(http.MethodGet, route.path, nil)
				w := httptest.NewRecorder()

				api.handler.ServeHTTP(w, r)

				require.Equal(t, http.StatusOK, w.Code)
				require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
				require.JSONEq(t, route.body, w.Body.String())
			})
		}

		t.Run("Returns a SCIM 403 when filter query param is used", func(t *testing.T) {
			for _, path := range []string{"/scim/v2/ResourceTypes", "/scim/v2/Schemas"} {
				t.Run(path, func(t *testing.T) {
					r := httptest.NewRequest(http.MethodGet, path+`?filter=name%20eq%20%22User%22`, nil)
					w := httptest.NewRecorder()

					api.handler.ServeHTTP(w, r)

					require.Equal(t, http.StatusForbidden, w.Code)
					assert.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
					assert.JSONEq(t, fixtures.FilterForbidden, w.Body.String())
				})
			}
		})

		t.Run("Returns a SCIM 404 error", func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/scim/v2/Unknown", nil)
			w := httptest.NewRecorder()

			api.handler.ServeHTTP(w, r)

			require.Equal(t, http.StatusNotFound, w.Code)
			require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
			require.JSONEq(t, fixtures.NotFound, w.Body.String())
		})

		t.Run("Returns a SCIM 405 error", func(t *testing.T) {
			for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
				for _, path := range []string{"/scim/v2/ServiceProviderConfig", "/scim/v2/ResourceTypes", "/scim/v2/Schemas"} {
					t.Run(method+" "+path, func(t *testing.T) {
						r := httptest.NewRequest(method, path, nil)
						w := httptest.NewRecorder()

						api.handler.ServeHTTP(w, r)

						require.Equal(t, http.StatusMethodNotAllowed, w.Code)
						require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
						require.Equal(t, "GET", w.Header().Get("Allow"))
						require.JSONEq(t, fixtures.MethodNotAllowed, w.Body.String())
					})
				}
			}
		})
	})
}
