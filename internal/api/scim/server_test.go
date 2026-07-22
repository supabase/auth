package scim

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServer(t *testing.T) {
	t.Run("NewServer", func(t *testing.T) {
		require.NotNil(t, NewServer())
	})

	srv := NewServer()
	for _, tc := range []struct {
		path    string
		handler func(http.ResponseWriter, *http.Request) error
	}{
		{"ResourceTypes", srv.ResourceTypes},
		{"Schemas", srv.Schemas},
	} {
		t.Run(tc.path, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/scim/v2/"+tc.path, nil)
			w := httptest.NewRecorder()

			require.NoError(t, tc.handler(w, r))
			require.Equal(t, w.Code, http.StatusNotImplemented)
			require.Equal(t, "application/scim+json", w.Header().Get("Content-Type"))
		})
	}

	t.Run("/scim/v2/ServiceProviderConfig", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/scim/v2/ServiceProviderConfig", nil)
		w := httptest.NewRecorder()

		require.NoError(t, srv.ServiceProviderConfig(w, r))
		require.Equal(t, w.Code, http.StatusOK)
		require.Equal(t, "application/scim+json", w.Header().Get("Content-Type"))

		cfg, err := FromJSON[*ServiceProviderConfiguration](w.Body)
		require.NoError(t, err)

		assert.Equal(t, []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"}, cfg.Schemas)
		assert.Equal(t, "https://supabase.com/docs/guides/auth/enterprise-sso/scim", cfg.DocumentationURI)
	})
}
