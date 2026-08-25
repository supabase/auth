package scim

import (
	"context"
	"embed"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api/scim/core"
	"github.com/supabase/auth/internal/api/scim/protocol"
)

const testExternalURL = "http://localhost:9999"

//go:embed testdata/*
var fixtures embed.FS

func testFixture(t *testing.T, file string) string {
	data, err := fixtures.ReadFile("testdata/" + file)
	require.NoError(t, err)
	return string(data)
}

func TestServer(t *testing.T) {
	srv := NewServer(testExternalURL)
	require.NotNil(t, srv)

	t.Run("NewServer trims a trailing slash from the external URL", func(t *testing.T) {
		location := NewServer("https://auth.example.com/").serviceProviderConfig.Meta.Location

		require.Equal(t, "https://auth.example.com"+BasePath+"/ServiceProviderConfig", location)
	})

	t.Run("GET /ServiceProviderConfig", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, BasePath+"/ServiceProviderConfig", nil)
		w := httptest.NewRecorder()

		require.NoError(t, srv.ServiceProviderConfig(w, r))

		require.Equal(t, http.StatusOK, w.Code)
		require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
		require.JSONEq(t, testFixture(t, "service_provider_config.json"), w.Body.String())
	})

	for _, tc := range []struct {
		path    string
		fixture string
		handler func(http.ResponseWriter, *http.Request) error
	}{
		{"ResourceTypes", "resource_types.json", srv.ResourceTypes},
		{"Schemas", "schemas.json", srv.Schemas},
	} {
		t.Run("GET /"+tc.path, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, BasePath+"/"+tc.path, nil)
			w := httptest.NewRecorder()

			require.NoError(t, tc.handler(w, r))

			require.Equal(t, http.StatusOK, w.Code)
			require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
			require.JSONEq(t, testFixture(t, tc.fixture), w.Body.String())
		})

		t.Run("GET /"+tc.path+" rejects a filter query parameter", func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, BasePath+"/"+tc.path+"?"+filterQuery(`name eq "User"`), nil)
			w := httptest.NewRecorder()

			require.NoError(t, tc.handler(w, r))

			require.Equal(t, http.StatusForbidden, w.Code)
			require.JSONEq(t, testFixture(t, "filter_forbidden.json"), w.Body.String())
		})
	}

	for _, tc := range []struct {
		name    string
		id      string
		fixture string
		handler func(http.ResponseWriter, *http.Request) error
	}{
		{"GET /ResourceTypes/User", "User", "resource_type_user.json", srv.ResourceTypeByID},
		{"GET /Schemas/{User URN}", string(core.SchemaUser), "schema_user.json", srv.SchemaByID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()

			require.NoError(t, tc.handler(w, requestWithURLParam(tc.id, "id", tc.id)))

			require.Equal(t, http.StatusOK, w.Code)
			require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
			require.JSONEq(t, testFixture(t, tc.fixture), w.Body.String())
		})
	}

	for _, tc := range []struct {
		name    string
		handler func(http.ResponseWriter, *http.Request) error
	}{
		{"GET /ResourceTypes/Unknown", srv.ResourceTypeByID},
		{"GET /Schemas/Unknown", srv.SchemaByID},
		{"GET /Unknown", srv.NotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()

			require.NoError(t, tc.handler(w, requestWithURLParam("Unknown", "id", "Unknown")))

			require.Equal(t, http.StatusNotFound, w.Code)
			require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
			require.JSONEq(t, testFixture(t, "not_found.json"), w.Body.String())
		})
	}
}

func requestWithURLParam(path, key, value string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, BasePath+"/"+path, nil)

	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add(key, value)

	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, routeCtx))
}

func filterQuery(filter string) string {
	return url.Values{"filter": {filter}}.Encode()
}
