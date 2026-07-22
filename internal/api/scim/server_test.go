package scim

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api/scim/fixtures"
	"github.com/supabase/auth/internal/api/scim/protocol"
	"github.com/supabase/auth/internal/conf/confload"
)

func TestServer(t *testing.T) {
	globalConfig, err := confload.LoadGlobal("../../../hack/test.env")
	require.NoError(t, err)
	srv := NewServer(globalConfig)

	for _, endpoint := range []struct {
		name    string
		handler func(http.ResponseWriter, *http.Request) error
		body    string
	}{
		{"ServiceProviderConfig", srv.ServiceProviderConfig, fixtures.ServiceProviderConfig},
		{"ResourceTypes", srv.ResourceTypes, fixtures.EmptyListResponse},
		{"Schemas", srv.Schemas, fixtures.EmptyListResponse},
	} {
		t.Run("GET "+BasePath+"/"+endpoint.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, BasePath+"/"+endpoint.name, nil)
			w := httptest.NewRecorder()

			require.NoError(t, endpoint.handler(w, r))
			require.Equal(t, http.StatusOK, w.Code)
			require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
			require.JSONEq(t, endpoint.body, w.Body.String())
		})
	}
}
