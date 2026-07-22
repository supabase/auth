package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/storage"
)

var scimPaths = []string{
	"/scim/v2/ServiceProviderConfig",
	"/scim/v2/ResourceTypes",
	"/scim/v2/Schemas",
}

func TestSCIM(t *testing.T) {
	t.Run("Disabled by default", func(t *testing.T) {
		api, _, err := setupAPIForTest()
		require.NoError(t, err)

		require.False(t, api.config.Experimental.ScimEnabled)
		require.Nil(t, api.scim)

		for _, path := range scimPaths {
			r := httptest.NewRequest(http.MethodGet, path, nil)
			w := httptest.NewRecorder()
			api.handler.ServeHTTP(w, r)

			require.Equal(t, w.Code, http.StatusNotFound)
		}
	})

	t.Run("Can be enabled", func(t *testing.T) {
		api, _, err := setupAPIForTestWithCallback(func(config *conf.GlobalConfiguration, conn *storage.Connection) {
			if config != nil {
				config.Experimental.ScimEnabled = true
			}
		})
		require.NoError(t, err)

		require.True(t, api.config.Experimental.ScimEnabled)
		require.NotNil(t, api.scim)
	})

	for _, path := range scimPaths {
		t.Run(path, func(t *testing.T) {
			api, _, err := setupAPIForTestWithCallback(func(config *conf.GlobalConfiguration, conn *storage.Connection) {
				if config != nil {
					config.Experimental.ScimEnabled = true
				}
			})
			require.NoError(t, err)

			r := httptest.NewRequest(http.MethodGet, path, nil)
			w := httptest.NewRecorder()
			api.handler.ServeHTTP(w, r)

			require.Equal(t, w.Code, http.StatusOK)
		})
	}
}
