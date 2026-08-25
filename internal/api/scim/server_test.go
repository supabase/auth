package scim

import (
	"context"
	"embed"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api/scim/core"
	"github.com/supabase/auth/internal/api/scim/protocol"
)

//go:embed testdata/*
var fixtures embed.FS

func testFixture(t *testing.T, file string) string {
	data, err := fixtures.ReadFile("testdata/" + file)
	require.NoError(t, err)
	return string(data)
}

func TestServer(t *testing.T) {
	db := newTestDB(t)
	srv := NewServer(db, testExternalURL)
	require.NotNil(t, srv)

	t.Run("NewServer trims a trailing slash from the external URL", func(t *testing.T) {
		location := NewServer(nil, "https://auth.example.com/").serviceProviderConfig.Meta.Location

		require.Equal(t, "https://auth.example.com"+BasePath+"/ServiceProviderConfig", location)
	})

	t.Run("Tenant", func(t *testing.T) {
		provider := newTenant(t, db)
		token := grantToken(t, db, provider)

		served := func(t *testing.T, authorization string) (*httptest.ResponseRecorder, string) {
			t.Helper()

			var seen string
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen, _ = tenantFrom(r.Context())
				w.WriteHeader(http.StatusTeapot)
			})

			r := httptest.NewRequest(http.MethodGet, BasePath+"/Users", nil)
			if authorization != "" {
				r.Header.Set("Authorization", authorization)
			}

			w := httptest.NewRecorder()
			srv.Tenant(next).ServeHTTP(w, r)
			return w, seen
		}

		t.Run("hands the tenant to the handler", func(t *testing.T) {
			w, seen := served(t, "Bearer "+token)

			assert.Equal(t, http.StatusTeapot, w.Code)
			assert.Equal(t, provider, seen)
		})

		t.Run("returns 401 with a challenge when the token is unknown", func(t *testing.T) {
			unknown, _ := NewToken()

			w, seen := served(t, "Bearer "+unknown)

			assert.Equal(t, http.StatusUnauthorized, w.Code)
			assert.Equal(t, `Bearer realm="SCIM"`, w.Header().Get("WWW-Authenticate"))
			assert.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
			assert.Empty(t, seen)
		})

		t.Run("returns 401 when there is no Authorization header", func(t *testing.T) {
			w, seen := served(t, "")

			assert.Equal(t, http.StatusUnauthorized, w.Code)
			assert.Empty(t, seen)
		})

		t.Run("returns 401 when the token is revoked", func(t *testing.T) {
			revoked := grantToken(t, db, provider)
			require.NoError(t, db.RawQuery("UPDATE scim_tokens SET revoked_at = now() WHERE token_hash = ?", hashToken(revoked)).Exec())

			w, seen := served(t, "Bearer "+revoked)

			assert.Equal(t, http.StatusUnauthorized, w.Code)
			assert.Equal(t, `Bearer realm="SCIM"`, w.Header().Get("WWW-Authenticate"))
			assert.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
			assert.Empty(t, seen)
		})

		t.Run("returns 401 when the token is expired", func(t *testing.T) {
			expired := grantToken(t, db, provider)
			require.NoError(t, db.RawQuery("UPDATE scim_tokens SET expires_at = now() - interval '1 second' WHERE token_hash = ?", hashToken(expired)).Exec())

			w, seen := served(t, "Bearer "+expired)

			assert.Equal(t, http.StatusUnauthorized, w.Code)
			assert.Empty(t, seen)
		})

		t.Run("returns 401 when the provider is disabled", func(t *testing.T) {
			other := newTenant(t, db)
			disabled := grantToken(t, db, other)
			require.NoError(t, db.RawQuery("UPDATE sso_providers SET disabled = true WHERE id = ?", other).Exec())

			w, seen := served(t, "Bearer "+disabled)

			assert.Equal(t, http.StatusUnauthorized, w.Code)
			assert.Empty(t, seen)
		})
	})

	t.Run("GET /Users/{id}", func(t *testing.T) {
		tenant := newTenant(t, db)

		t.Run("returns the resource", func(t *testing.T) {
			stored := newStoredUser(t, db, tenant, &core.User{UserName: "bjensen@example.com"})

			w := httptest.NewRecorder()
			require.NoError(t, srv.UserByID(w, scimRequest(http.MethodGet, "/Users/"+stored.ID, "", tenant, map[string]string{"id": stored.ID})))

			require.Equal(t, http.StatusOK, w.Code)
			require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))

			var got core.User
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
			assert.Equal(t, stored.ID, got.ID)
			assert.Equal(t, "bjensen@example.com", got.UserName)
		})

		t.Run("an unknown id is a SCIM 404", func(t *testing.T) {
			missing := uuid.Must(uuid.NewV4()).String()

			w := httptest.NewRecorder()
			require.NoError(t, srv.UserByID(w, scimRequest(http.MethodGet, "/Users/"+missing, "", tenant, map[string]string{"id": missing})))

			require.Equal(t, http.StatusNotFound, w.Code)
			require.JSONEq(t, testFixture(t, "not_found.json"), w.Body.String())
		})

		// An id that is not a uuid can never name a row, so it is answered as a
		// missing resource rather than surfacing a parse error.
		t.Run("an id that is not a uuid is a SCIM 404", func(t *testing.T) {
			w := httptest.NewRecorder()
			require.NoError(t, srv.UserByID(w, scimRequest(http.MethodGet, "/Users/not-a-uuid", "", tenant, map[string]string{"id": "not-a-uuid"})))

			require.Equal(t, http.StatusNotFound, w.Code)
			require.JSONEq(t, testFixture(t, "not_found.json"), w.Body.String())
		})

		t.Run("another tenant's resource is a SCIM 404", func(t *testing.T) {
			other := newTenant(t, db)
			stored := newStoredUser(t, db, other, &core.User{UserName: "theirs@example.com"})

			w := httptest.NewRecorder()
			require.NoError(t, srv.UserByID(w, scimRequest(http.MethodGet, "/Users/"+stored.ID, "", tenant, map[string]string{"id": stored.ID})))

			require.Equal(t, http.StatusNotFound, w.Code)
		})
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

func scimRequest(method, target, body, tenant string, params map[string]string) *http.Request {
	r := httptest.NewRequest(method, BasePath+target, strings.NewReader(body))

	routeCtx := chi.NewRouteContext()
	for key, value := range params {
		routeCtx.URLParams.Add(key, value)
	}

	ctx := context.WithValue(r.Context(), chi.RouteCtxKey, routeCtx)
	return r.WithContext(withTenant(ctx, tenant))
}
