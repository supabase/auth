package scim

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/supabase/auth/internal/api/scim/core"
	"github.com/supabase/auth/internal/api/scim/protocol"
	"github.com/supabase/auth/internal/models"
)

func TestServer(t *testing.T) {
	srv := NewServer(nil)
	require.NotNil(t, srv)

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
			require.Equal(t, http.StatusOK, w.Code)
			require.Equal(t, "application/scim+json", w.Header().Get("Content-Type"))

			var list protocol.ListResponse[any]
			require.NoError(t, json.NewDecoder(w.Body).Decode(&list))

			assert.Equal(t, []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"}, list.Schemas)
			assert.Equal(t, 0, list.TotalResults)
			assert.Empty(t, list.Resources)
		})
	}

	t.Run("/scim/v2/ServiceProviderConfig", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/scim/v2/ServiceProviderConfig", nil)
		w := httptest.NewRecorder()

		require.NoError(t, srv.ServiceProviderConfig(w, r))
		require.Equal(t, http.StatusOK, w.Code)
		require.Equal(t, "application/scim+json", w.Header().Get("Content-Type"))

		var cfg core.ServiceProviderConfig
		require.NoError(t, json.NewDecoder(w.Body).Decode(&cfg))

		assert.Equal(t, []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"}, cfg.Schemas)
		assert.Empty(t, cfg.DocumentationURI)
		assert.False(t, cfg.Patch.Supported)
		assert.False(t, cfg.Bulk.Supported)
		assert.False(t, cfg.Filter.Supported)
		assert.False(t, cfg.ChangePassword.Supported)
		assert.False(t, cfg.Sort.Supported)
		assert.False(t, cfg.ETag.Supported)
		require.Len(t, cfg.AuthenticationSchemes, 1)
		scheme := cfg.AuthenticationSchemes[0]
		assert.Equal(t, "oauthbearertoken", scheme.Type)
		assert.Equal(t, "OAuth Bearer Token", scheme.Name)
		assert.Equal(t, "http://www.rfc-editor.org/info/rfc6750", scheme.SpecURI)
		assert.NotEmpty(t, scheme.Description)
		assert.True(t, scheme.Primary)
	})

	t.Run("/scim/v2/Users/:id", func(t *testing.T) {
		user, err := models.NewUser("12345678", "test1@example.com", "test", "", nil)
		require.NoError(t, err)

		r := httptest.NewRequest(http.MethodGet, "/scim/v2/Users"+user.ID.String(), nil)
		w := httptest.NewRecorder()

		require.NoError(t, srv.GetUser(w, r))
		require.Equal(t, http.StatusOK, w.Code)
		require.Equal(t, "application/scim+json", w.Header().Get("Content-Type"))
	})
}
