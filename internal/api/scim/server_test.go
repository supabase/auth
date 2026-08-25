package scim

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
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
	"github.com/supabase/auth/internal/storage"
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

	t.Run("NewServer", func(t *testing.T) {
		location := NewServer(nil, "https://auth.example.com/").serviceProviderConfig.Meta.Location

		require.Equal(t, "https://auth.example.com/scim/v2/ServiceProviderConfig", location)
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

		t.Run("returns 401 when token is revoked", func(t *testing.T) {
			revoked := grantToken(t, db, provider)
			require.NoError(t, db.RawQuery("UPDATE scim_tokens SET revoked_at = now() WHERE token_hash = ?", hashToken(revoked)).Exec())

			w, seen := served(t, "Bearer "+revoked)
			assert.Empty(t, seen)
			assert.Equal(t, http.StatusUnauthorized, w.Code)
			assert.Equal(t, `Bearer realm="SCIM"`, w.Header().Get("WWW-Authenticate"))
			assert.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
		})
	})

	t.Run("GET /ServiceProviderConfig", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/scim/v2/ServiceProviderConfig", nil)
		w := httptest.NewRecorder()

		require.NoError(t, srv.ServiceProviderConfig(w, r))

		require.Equal(t, http.StatusOK, w.Code)
		require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
		require.JSONEq(t, testFixture(t, "service_provider_config.json"), w.Body.String())
	})

	t.Run("GET /ResourceTypes", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/scim/v2/ResourceTypes", nil)
		w := httptest.NewRecorder()

		require.NoError(t, srv.ResourceTypes(w, r))

		require.Equal(t, http.StatusOK, w.Code)
		require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
		require.JSONEq(t, testFixture(t, "resource_types.json"), w.Body.String())
	})

	t.Run("GET /ResourceTypes?filter={name eq User}", func(t *testing.T) {
		filter := url.Values{"filter": {`name eq "User"`}}.Encode()
		r := httptest.NewRequest(http.MethodGet, "/scim/v2/ResourceTypes"+"?"+filter, nil)
		w := httptest.NewRecorder()

		require.NoError(t, srv.ResourceTypes(w, r))

		require.Equal(t, http.StatusForbidden, w.Code)
		require.JSONEq(t, testFixture(t, "filter_forbidden.json"), w.Body.String())
	})

	t.Run("GET /ResourceTypes/User", func(t *testing.T) {
		r := requestWithURLParam("/ResourceTypes/User", "id", "User")
		w := httptest.NewRecorder()

		require.NoError(t, srv.ResourceTypeByID(w, r))

		require.Equal(t, http.StatusOK, w.Code)
		require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
		require.JSONEq(t, testFixture(t, "resource_type_user.json"), w.Body.String())
	})

	t.Run("GET /ResourceTypes/Unknown", func(t *testing.T) {
		r := requestWithURLParam("/ResourceTypes/Unknown", "id", "Unknown")
		w := httptest.NewRecorder()

		require.NoError(t, srv.ResourceTypeByID(w, r))

		require.Equal(t, http.StatusNotFound, w.Code)
		require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
		require.JSONEq(t, testFixture(t, "not_found.json"), w.Body.String())
	})

	t.Run("GET /Schemas", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/scim/v2/Schemas", nil)
		w := httptest.NewRecorder()

		require.NoError(t, srv.Schemas(w, r))

		require.Equal(t, http.StatusOK, w.Code)
		require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
		require.JSONEq(t, testFixture(t, "schemas.json"), w.Body.String())
	})

	t.Run("GET /Schemas?filter={name eq User}", func(t *testing.T) {
		filter := url.Values{"filter": {`name eq "User"`}}.Encode()
		r := httptest.NewRequest(http.MethodGet, "/scim/v2/Schemas"+"?"+filter, nil)
		w := httptest.NewRecorder()

		require.NoError(t, srv.Schemas(w, r))

		require.Equal(t, http.StatusForbidden, w.Code)
		require.JSONEq(t, testFixture(t, "filter_forbidden.json"), w.Body.String())
	})

	t.Run("GET /Schemas/User", func(t *testing.T) {
		r := requestWithURLParam("/Schemas/urn:ietf:params:scim:schemas:core:2.0:User", "id", "urn:ietf:params:scim:schemas:core:2.0:User")
		w := httptest.NewRecorder()

		require.NoError(t, srv.SchemaByID(w, r))

		require.Equal(t, http.StatusOK, w.Code)
		require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
		require.JSONEq(t, testFixture(t, "schema_user.json"), w.Body.String())
	})

	t.Run("GET /Schemas/Unknown", func(t *testing.T) {
		r := requestWithURLParam("/Schemas/Unknown", "id", "Unknown")
		w := httptest.NewRecorder()

		require.NoError(t, srv.SchemaByID(w, r))

		require.Equal(t, http.StatusNotFound, w.Code)
		require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
		require.JSONEq(t, testFixture(t, "not_found.json"), w.Body.String())
	})

	t.Run("GET /scim/v2/Unknown", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/scim/v2/Unknown", nil)
		w := httptest.NewRecorder()

		require.NoError(t, srv.NotFound(w, r))

		require.Equal(t, http.StatusNotFound, w.Code)
		require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
		require.JSONEq(t, testFixture(t, "not_found.json"), w.Body.String())
	})

	t.Run("GET /Users", func(t *testing.T) {
		t.Run("?startIndex=first", func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/scim/v2/Users?startIndex=first", nil)
			w := httptest.NewRecorder()

			require.NoError(t, srv.Users(w, r))

			require.Equal(t, http.StatusBadRequest, w.Code)
			require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))

			var body protocol.Error
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
			assert.Equal(t, protocol.ScimTypeInvalidValue, body.ScimType)
		})

		t.Run("?count=all", func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/scim/v2/Users?count=all", nil)
			w := httptest.NewRecorder()

			require.NoError(t, srv.Users(w, r))

			require.Equal(t, http.StatusBadRequest, w.Code)
			require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))

			var body protocol.Error
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
			assert.Equal(t, protocol.ScimTypeInvalidValue, body.ScimType)
		})

		t.Run("?startIndex=2&count=2", func(t *testing.T) {
			get := usersFor(t, srv, db, "a", "b", "c", "d", "e")

			w := get("startIndex=2&count=2")
			body := listed[*core.User](t, w)

			require.Equal(t, http.StatusOK, w.Code)
			assert.Equal(t, 5, body.TotalResults)
			assert.Equal(t, 2, body.StartIndex)
			assert.Equal(t, 2, body.ItemsPerPage)
			assert.Len(t, body.Resources, 2)
		})

		t.Run("?count=0", func(t *testing.T) {
			get := usersFor(t, srv, db, "a", "b", "c")

			w := get("count=0")
			body := listed[*core.User](t, w)

			require.Equal(t, http.StatusOK, w.Code)
			assert.Equal(t, 3, body.TotalResults)
			assert.Equal(t, 0, body.ItemsPerPage)
			assert.Empty(t, body.Resources)
			assert.Contains(t, w.Body.String(), `"Resources":[]`)
		})

		t.Run("sortBy=userName", func(t *testing.T) {
			get := usersFor(t, srv, db, "carol", "alice", "bob")

			ascending := listed[*core.User](t, get("sortBy=userName"))
			descending := listed[*core.User](t, get("sortBy=userName&sortOrder=descending"))

			assert.Equal(t, []string{"alice", "bob", "carol"}, userNamesOf(ascending.Resources))
			assert.Equal(t, []string{"carol", "bob", "alice"}, userNamesOf(descending.Resources))
		})

		t.Run("?sortBy=nickName", func(t *testing.T) {
			get := usersFor(t, srv, db, "a")

			w := get("sortBy=nickName")

			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
			assert.Contains(t, w.Body.String(), string(protocol.ScimTypeInvalidValue))
			assert.Contains(t, w.Body.String(), "nickName")
		})

		t.Run("?sortBy=userName&sortOrder=sideways", func(t *testing.T) {
			get := usersFor(t, srv, db, "a")

			w := get("sortBy=userName&sortOrder=sideways")

			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.Contains(t, w.Body.String(), string(protocol.ScimTypeInvalidValue))
		})

		t.Run("?filter is rejected", func(t *testing.T) {
			get := usersFor(t, srv, db, "alice", "bob", "carol")

			w := get(filterQuery(`userName eq "bob"`))

			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
			assert.Contains(t, w.Body.String(), string(protocol.ScimTypeInvalidFilter))
		})
	})

	create := func(t *testing.T, srv *Server, tenant, userName string) *core.User {
		t.Helper()
		r := scimRequest(http.MethodPost, "/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"`+userName+`"}`, tenant, nil)
		w := httptest.NewRecorder()
		require.NoError(t, srv.CreateUser(w, r))
		require.Equal(t, http.StatusCreated, w.Code)

		var user core.User
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &user))
		return &user
	}

	t.Run("POST /Users", func(t *testing.T) {
		t.Run("with valid parameters", func(t *testing.T) {
			tenant := newTenant(t, db)

			r := scimRequest(http.MethodPost, "/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"bjensen"}`, tenant, nil)
			w := httptest.NewRecorder()
			require.NoError(t, srv.CreateUser(w, r))

			require.Equal(t, http.StatusCreated, w.Code)
			require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))

			var user core.User
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &user))
			assert.NotEmpty(t, user.ID)
			assert.Equal(t, "bjensen", user.UserName)
			assert.Equal(t, testExternalURL+BasePath+"/Users/"+user.ID, w.Header().Get("Location"))
		})

		t.Run("defaults active to true when omitted", func(t *testing.T) {
			tenant := newTenant(t, db)

			r := scimRequest(http.MethodPost, "/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"bjensen"}`, tenant, nil)
			w := httptest.NewRecorder()
			require.NoError(t, srv.CreateUser(w, r))

			require.Equal(t, http.StatusCreated, w.Code)

			var user core.User
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &user))
			require.NotNil(t, user.Active)
			assert.True(t, *user.Active)
		})

		t.Run("without a userName", func(t *testing.T) {
			tenant := newTenant(t, db)

			r := scimRequest(http.MethodPost, "/Users", `{"externalId":"ext-1"}`, tenant, nil)
			w := httptest.NewRecorder()
			require.NoError(t, srv.CreateUser(w, r))

			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.Contains(t, w.Body.String(), string(protocol.ScimTypeInvalidValue))
		})

		t.Run("with a malformed body", func(t *testing.T) {
			tenant := newTenant(t, db)

			r := scimRequest(http.MethodPost, "/Users", `{"userName":`, tenant, nil)
			w := httptest.NewRecorder()
			require.NoError(t, srv.CreateUser(w, r))

			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.Contains(t, w.Body.String(), string(protocol.ScimTypeInvalidSyntax))
		})

		t.Run("with an oversized request body", func(t *testing.T) {
			tenant := newTenant(t, db)

			body := fmt.Sprintf(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"%s"}`, strings.Repeat("x", 64))
			r := httptest.
				NewRequest(http.MethodPost, "/scim/v2/Users", strings.NewReader(body)).
				WithContext(withTenant(t.Context(), tenant))
			r.Body = http.MaxBytesReader(httptest.NewRecorder(), r.Body, 8)

			w := httptest.NewRecorder()

			require.NoError(t, srv.CreateUser(w, r))

			require.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
			require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
		})
	})

	t.Run("PUT /Users/{id}", func(t *testing.T) {
		t.Run("replaces a User's attributes", func(t *testing.T) {
			tenant := newTenant(t, db)
			created := create(t, srv, tenant, "carol")

			body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"carol-renamed"}`
			r := scimRequest(http.MethodPut, "/Users/"+created.ID, body, tenant, map[string]string{"id": created.ID})
			w := httptest.NewRecorder()
			require.NoError(t, srv.ReplaceUser(w, r))

			require.Equal(t, http.StatusOK, w.Code)
			var user core.User
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &user))
			assert.Equal(t, created.ID, user.ID)
			assert.Equal(t, "carol-renamed", user.UserName)
		})

		t.Run("with an unknown id", func(t *testing.T) {
			tenant := newTenant(t, db)
			id := uuid.Must(uuid.NewV4()).String()

			r := scimRequest(http.MethodPut, "/Users/"+id, `{"userName":"ghost"}`, tenant, map[string]string{"id": id})
			w := httptest.NewRecorder()
			require.NoError(t, srv.ReplaceUser(w, r))

			assert.Equal(t, http.StatusNotFound, w.Code)
		})
	})

	t.Run("DELETE /Users", func(t *testing.T) {
		t.Run("removes a User", func(t *testing.T) {
			tenant := newTenant(t, db)
			created := create(t, srv, tenant, "eve")

			r := scimRequest(http.MethodDelete, "/Users/"+created.ID, "", tenant, map[string]string{"id": created.ID})
			w := httptest.NewRecorder()
			require.NoError(t, srv.DeleteUser(w, r))

			require.Equal(t, http.StatusNoContent, w.Code)
			assert.Empty(t, w.Body.String())

			get := scimRequest(http.MethodGet, "/Users/"+created.ID, "", tenant, map[string]string{"id": created.ID})
			gw := httptest.NewRecorder()
			require.NoError(t, srv.UserByID(gw, get))
			assert.Equal(t, http.StatusNotFound, gw.Code)
		})

		t.Run("with an unknown", func(t *testing.T) {
			tenant := newTenant(t, db)
			id := uuid.Must(uuid.NewV4()).String()

			r := scimRequest(http.MethodDelete, "/Users/"+id, "", tenant, map[string]string{"id": id})
			w := httptest.NewRecorder()
			require.NoError(t, srv.DeleteUser(w, r))

			assert.Equal(t, http.StatusNotFound, w.Code)
		})
	})
}

func requestWithURLParam(path, key, value string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/scim/v2/"+path, nil)

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

func usersFor(t *testing.T, srv *Server, db *storage.Connection, userNames ...string) func(query string) *httptest.ResponseRecorder {
	t.Helper()

	tenant := newTenant(t, db)
	for _, userName := range userNames {
		newStoredUser(t, db, tenant, &core.User{UserName: userName})
	}

	return func(query string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, BasePath+"/Users?"+query, nil)
		r = r.WithContext(withTenant(r.Context(), tenant))

		w := httptest.NewRecorder()
		require.NoError(t, srv.Users(w, r))
		return w
	}
}

func listed[T any](t *testing.T, w *httptest.ResponseRecorder) protocol.ListResponse[T] {
	t.Helper()

	var body protocol.ListResponse[T]
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	return body
}
