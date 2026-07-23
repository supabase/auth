package scim

import (
	"net/http"
	"net/http/httptest"
	"testing"

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
		{"ServiceProviderConfig", srv.ServiceProviderConfig},
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
}
