package scim

import (
	"context"
	"embed"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api/scim/protocol"
)

//go:embed testdata/*
var fixtures embed.FS

func testFixture(t *testing.T, file string) string {
	data, err := fixtures.ReadFile("testdata/" + file)
	require.NoError(t, err)
	return string(data)
}

func newServerFor(externalURL string) *Server {
	return NewServer(Config{
		ExternalURL: externalURL,
		Users:       NewMemoryUserStore(),
	})
}

func TestReadBodyRejectsATooLargeBody(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("x", 64)))
	r.Body = http.MaxBytesReader(httptest.NewRecorder(), r.Body, 8)

	_, err := readBody(r)
	require.ErrorIs(t, err, protocol.ErrTooLarge(""), "an oversized body is 413, not 400")
}

func TestServer(t *testing.T) {
	srv := newServerFor("http://localhost:9999")
	require.NotNil(t, srv)

	t.Run("NewServer trims a trailing slash from the external URL", func(t *testing.T) {
		location := newServerFor("https://auth.example.com/").serviceProviderConfig.Meta.Location

		require.Equal(t, "https://auth.example.com"+BasePath+"/ServiceProviderConfig", location)
	})

	t.Run("/ServiceProviderConfig", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, BasePath+"/ServiceProviderConfig", nil)
		w := httptest.NewRecorder()

		require.NoError(t, srv.ServiceProviderConfig(w, r))

		require.Equal(t, http.StatusOK, w.Code)
		require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
		require.JSONEq(t, testFixture(t, "service_provider_config.json"), w.Body.String())
	})

	t.Run("/ResourceTypes", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/scim/v2/ResourceTypes", nil)
		w := httptest.NewRecorder()

		require.NoError(t, srv.ResourceTypes(w, r))

		require.Equal(t, http.StatusOK, w.Code)
		require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
		require.JSONEq(t, testFixture(t, "resource_types.json"), w.Body.String())
	})

	t.Run("/ResourceTypes?filter={name eq User}", func(t *testing.T) {
		filter := url.Values{"filter": {`name eq "User"`}}.Encode()
		r := httptest.NewRequest(http.MethodGet, "/scim/v2/ResourceTypes"+"?"+filter, nil)
		w := httptest.NewRecorder()

		require.NoError(t, srv.ResourceTypes(w, r))

		require.Equal(t, http.StatusForbidden, w.Code)
		require.JSONEq(t, testFixture(t, "filter_forbidden.json"), w.Body.String())
	})

	t.Run("/ResourceTypes/User", func(t *testing.T) {
		r := requestWithURLParam("/ResourceTypes/User", "id", "User")
		w := httptest.NewRecorder()

		require.NoError(t, srv.ResourceTypeByID(w, r))

		require.Equal(t, http.StatusOK, w.Code)
		require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
		require.JSONEq(t, testFixture(t, "resource_type_user.json"), w.Body.String())
	})

	t.Run("/ResourceTypes/Unknown", func(t *testing.T) {
		r := requestWithURLParam("/ResourceTypes/Unknown", "id", "Unknown")
		w := httptest.NewRecorder()

		require.NoError(t, srv.ResourceTypeByID(w, r))

		require.Equal(t, http.StatusNotFound, w.Code)
		require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
		require.JSONEq(t, testFixture(t, "not_found.json"), w.Body.String())
	})

	t.Run("/Schemas", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/scim/v2/Schemas", nil)
		w := httptest.NewRecorder()

		require.NoError(t, srv.Schemas(w, r))

		require.Equal(t, http.StatusOK, w.Code)
		require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
		require.JSONEq(t, testFixture(t, "schemas.json"), w.Body.String())
	})

	t.Run("/Schemas?filter={name eq User}", func(t *testing.T) {
		filter := url.Values{"filter": {`name eq "User"`}}.Encode()
		r := httptest.NewRequest(http.MethodGet, "/scim/v2/Schemas"+"?"+filter, nil)
		w := httptest.NewRecorder()

		require.NoError(t, srv.Schemas(w, r))

		require.Equal(t, http.StatusForbidden, w.Code)
		require.JSONEq(t, testFixture(t, "filter_forbidden.json"), w.Body.String())
	})

	t.Run("/Schemas/User", func(t *testing.T) {
		r := requestWithURLParam("/Schemas/urn:ietf:params:scim:schemas:core:2.0:User", "id", "urn:ietf:params:scim:schemas:core:2.0:User")
		w := httptest.NewRecorder()

		require.NoError(t, srv.SchemaByID(w, r))

		require.Equal(t, http.StatusOK, w.Code)
		require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
		require.JSONEq(t, testFixture(t, "schema_user.json"), w.Body.String())
	})

	t.Run("/Schemas/Unknown", func(t *testing.T) {
		r := requestWithURLParam("/Schemas/Unknown", "id", "Unknown")
		w := httptest.NewRecorder()

		require.NoError(t, srv.SchemaByID(w, r))

		require.Equal(t, http.StatusNotFound, w.Code)
		require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
		require.JSONEq(t, testFixture(t, "not_found.json"), w.Body.String())
	})

	t.Run("NotFound", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, BasePath+"/Unknown", nil)
		w := httptest.NewRecorder()

		require.NoError(t, srv.NotFound(w, r))

		require.Equal(t, http.StatusNotFound, w.Code)
		require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
		require.JSONEq(t, testFixture(t, "not_found.json"), w.Body.String())
	})

	t.Run("Users rejects pagination parameters that are not integers", func(t *testing.T) {
		for _, query := range []string{"startIndex=first", "count=all"} {
			t.Run(query, func(t *testing.T) {
				r := httptest.NewRequest(http.MethodGet, BasePath+"/Users?"+query, nil)
				w := httptest.NewRecorder()

				require.NoError(t, srv.Users(w, r))

				require.Equal(t, http.StatusBadRequest, w.Code)
				require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
				require.Contains(t, w.Body.String(), string(protocol.ScimTypeInvalidValue))
			})
		}
	})

	t.Run("Users without a tenant on the context is a server error", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, BasePath+"/Users", nil)
		w := httptest.NewRecorder()

		require.NoError(t, srv.Users(w, r))

		require.Equal(t, http.StatusNotFound, w.Code)
		require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
	})

	t.Run("UserByID without a tenant on the context is a server error", func(t *testing.T) {
		id := uuid.Must(uuid.NewV4()).String()
		r := requestWithURLParam("Users/"+id, "id", id)
		w := httptest.NewRecorder()

		require.NoError(t, srv.UserByID(w, r))

		require.Equal(t, http.StatusNotFound, w.Code)
		require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
	})
}

func requestWithURLParam(path, key, value string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, BasePath+"/"+path, nil)

	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add(key, value)

	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, routeCtx))
}
