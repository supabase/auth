package scim

import (
	"embed"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

//go:embed testdata/*
var fixtures embed.FS

func testFixture(t *testing.T, file string) string {
	data, err := fixtures.ReadFile("testdata/" + file)
	require.NoError(t, err)
	return string(data)
}

func TestServer(t *testing.T) {
	srv := NewServer(nil)
	require.NotNil(t, srv)

	for _, tc := range []struct {
		path    string
		handler func(http.ResponseWriter, *http.Request) error
	}{
		{"ServiceProviderConfig", srv.ServiceProviderConfig},
		{"ResourceTypes", srv.ResourceTypes},
		{"Schemas", srv.Schemas},
	} {
		t.Run(tc.path, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, BasePath+"/"+tc.path, nil)
			w := httptest.NewRecorder()

			require.NoError(t, tc.handler(w, r))
			require.Equal(t, http.StatusNotImplemented, w.Code)
			require.Equal(t, "application/scim+json", w.Header().Get("Content-Type"))
			require.JSONEq(t, testFixture(t, "not_implemented.json"), w.Body.String())
		})
	}

	t.Run("NotFound", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, BasePath+"/Unknown", nil)
		w := httptest.NewRecorder()

		require.NoError(t, srv.NotFound(w, r))

		require.Equal(t, http.StatusNotFound, w.Code)
		require.Equal(t, "application/scim+json", w.Header().Get("Content-Type"))
		require.JSONEq(t, testFixture(t, "not_found.json"), w.Body.String())
	})
}
