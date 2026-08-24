package scim

import (
	"context"
	"embed"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
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

		require.Equal(t, "https://auth.example.com/scim/v2/ServiceProviderConfig", location)
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
		t.Run("Unauthenticated", func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
			w := httptest.NewRecorder()

			require.NoError(t, srv.Users(w, r))

			require.Equal(t, http.StatusNotFound, w.Code)
			require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
			require.JSONEq(t, testFixture(t, "not_found.json"), w.Body.String())
		})

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
			_, get := usersFor(t, "a", "b", "c", "d", "e")

			w := get("startIndex=2&count=2")
			body := listed[*core.User](t, w)

			require.Equal(t, http.StatusOK, w.Code)
			assert.Equal(t, 5, body.TotalResults)
			assert.Equal(t, 2, body.StartIndex)
			assert.Equal(t, 2, body.ItemsPerPage)
			assert.Len(t, body.Resources, 2)
		})

		t.Run("?count=0", func(t *testing.T) {
			_, get := usersFor(t, "a", "b", "c")

			w := get("count=0")
			body := listed[*core.User](t, w)

			require.Equal(t, http.StatusOK, w.Code)
			assert.Equal(t, 3, body.TotalResults)
			assert.Equal(t, 0, body.ItemsPerPage)
			assert.Empty(t, body.Resources)
			assert.Contains(t, w.Body.String(), `"Resources":[]`)
		})

		t.Run("sortBy=userName", func(t *testing.T) {
			_, get := usersFor(t, "carol", "alice", "bob")

			ascending := listed[*core.User](t, get("sortBy=userName"))
			descending := listed[*core.User](t, get("sortBy=userName&sortOrder=descending"))

			assert.Equal(t, []string{"alice", "bob", "carol"}, userNamesOf(ascending.Resources))
			assert.Equal(t, []string{"carol", "bob", "alice"}, userNamesOf(descending.Resources))
		})

		t.Run("?sortBy=nickName", func(t *testing.T) {
			_, get := usersFor(t, "a")

			w := get("sortBy=nickName")

			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
			assert.Contains(t, w.Body.String(), string(protocol.ScimTypeInvalidValue))
			assert.Contains(t, w.Body.String(), "nickName")
		})

		t.Run("?sortBy=userName&sortOrder=sideways", func(t *testing.T) {
			_, get := usersFor(t, "a")

			w := get("sortBy=userName&sortOrder=sideways")

			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.Contains(t, w.Body.String(), string(protocol.ScimTypeInvalidValue))
		})

		t.Run(`?filter=userName eq "bob"`, func(t *testing.T) {
			_, get := usersFor(t, "alice", "bob", "carol")

			body := listed[*core.User](t, get(filterQuery(`userName eq "bob"`)))

			assert.Equal(t, 1, body.TotalResults)
			assert.Equal(t, []string{"bob"}, userNamesOf(body.Resources))
		})

		t.Run(`?filter=userName sw "a"`, func(t *testing.T) {
			_, get := usersFor(t, "ann", "abe", "bob")

			body := listed[*core.User](t, get(filterQuery(`userName sw "a"`)))

			assert.Equal(t, 2, body.TotalResults)
		})

		t.Run(`?filter=userName eq "bjensen"`, func(t *testing.T) {
			_, get := usersFor(t, "BJensen")

			body := listed[*core.User](t, get(filterQuery(`userName eq "bjensen"`)))

			assert.Equal(t, 1, body.TotalResults)
		})

		t.Run(`?filter=emails[type eq "work"`, func(t *testing.T) {
			_, get := usersFor(t, "a")

			w := get(filterQuery(`emails[type eq "work"]`))

			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
			assert.Contains(t, w.Body.String(), string(protocol.ScimTypeInvalidFilter))
		})

		t.Run("?filter=userName eq", func(t *testing.T) {
			_, get := usersFor(t, "a")

			w := get(filterQuery(`userName eq`))

			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.Contains(t, w.Body.String(), string(protocol.ScimTypeInvalidFilter))
		})
	})

	t.Run("GET /Users/{id}", func(t *testing.T) {
		t.Run("Unauthenticated", func(t *testing.T) {
			id := uuid.Must(uuid.NewV4()).String()
			r := requestWithURLParam("Users/"+id, "id", id)
			w := httptest.NewRecorder()

			require.NoError(t, srv.UserByID(w, r))

			require.Equal(t, http.StatusNotFound, w.Code)
			require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
			require.JSONEq(t, testFixture(t, "not_found.json"), w.Body.String())
		})
	})

	t.Run("POST /Users", func(t *testing.T) {
		create := func(t *testing.T, srv *Server, userName string) *core.User {
			t.Helper()
			r := scimRequest(http.MethodPost, "/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"`+userName+`"}`, nil)
			w := httptest.NewRecorder()
			require.NoError(t, srv.CreateUser(w, r))
			require.Equal(t, http.StatusCreated, w.Code)

			var user core.User
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &user))
			return &user
		}

		t.Run("POST creates a User and answers 201 with a Location", func(t *testing.T) {
			srv := newServerFor("http://localhost:9999")

			r := scimRequest(http.MethodPost, "/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"bjensen"}`, nil)
			w := httptest.NewRecorder()
			require.NoError(t, srv.CreateUser(w, r))

			require.Equal(t, http.StatusCreated, w.Code)
			require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))

			var user core.User
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &user))
			assert.NotEmpty(t, user.ID)
			assert.Equal(t, "bjensen", user.UserName)
			assert.Equal(t, "http://localhost:9999"+BasePath+"/Users/"+user.ID, w.Header().Get("Location"))
		})

		t.Run("POST without a userName is a bad request", func(t *testing.T) {
			srv := newServerFor("http://localhost:9999")

			r := scimRequest(http.MethodPost, "/Users", `{"externalId":"ext-1"}`, nil)
			w := httptest.NewRecorder()
			require.NoError(t, srv.CreateUser(w, r))

			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.Contains(t, w.Body.String(), string(protocol.ScimTypeInvalidValue))
		})

		t.Run("POST of a malformed body is a bad request", func(t *testing.T) {
			srv := newServerFor("http://localhost:9999")

			r := scimRequest(http.MethodPost, "/Users", `{"userName":`, nil)
			w := httptest.NewRecorder()
			require.NoError(t, srv.CreateUser(w, r))

			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.Contains(t, w.Body.String(), string(protocol.ScimTypeInvalidSyntax))
		})

		t.Run("PUT replaces a User's attributes", func(t *testing.T) {
			srv := newServerFor("http://localhost:9999")
			created := create(t, srv, "carol")

			r := scimRequest(http.MethodPut, "/Users/"+created.ID, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"carol-renamed"}`,
				map[string]string{"id": created.ID})
			w := httptest.NewRecorder()
			require.NoError(t, srv.ReplaceUser(w, r))

			require.Equal(t, http.StatusOK, w.Code)
			var user core.User
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &user))
			assert.Equal(t, created.ID, user.ID)
			assert.Equal(t, "carol-renamed", user.UserName)
		})

		t.Run("PUT of an unknown id is not found", func(t *testing.T) {
			srv := newServerFor("http://localhost:9999")
			id := uuid.Must(uuid.NewV4()).String()

			r := scimRequest(http.MethodPut, "/Users/"+id, `{"userName":"ghost"}`, map[string]string{"id": id})
			w := httptest.NewRecorder()
			require.NoError(t, srv.ReplaceUser(w, r))

			assert.Equal(t, http.StatusNotFound, w.Code)
		})

		t.Run("PATCH deactivates a User", func(t *testing.T) {
			srv := newServerFor("http://localhost:9999")
			created := create(t, srv, "dave")

			r := scimRequest(http.MethodPatch, "/Users/"+created.ID, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","value":{"active":false}}]}`, map[string]string{"id": created.ID})
			w := httptest.NewRecorder()
			require.NoError(t, srv.PatchUser(w, r))

			require.Equal(t, http.StatusOK, w.Code)
			var user core.User
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &user))
			require.NotNil(t, user.Active)
			assert.False(t, *user.Active)
		})

		t.Run("PATCH of an unknown id is not found", func(t *testing.T) {
			srv := newServerFor("http://localhost:9999")
			id := uuid.Must(uuid.NewV4()).String()

			r := scimRequest(http.MethodPatch, "/Users/"+id, `{"Operations":[{"op":"replace","value":{"active":false}}]}`, map[string]string{"id": id})
			w := httptest.NewRecorder()
			require.NoError(t, srv.PatchUser(w, r))

			assert.Equal(t, http.StatusNotFound, w.Code)
		})

		t.Run("PATCH of a malformed body is a bad request", func(t *testing.T) {
			srv := newServerFor("http://localhost:9999")
			created := create(t, srv, "erin")

			r := scimRequest(http.MethodPatch, "/Users/"+created.ID, `{"Operations":[{"op":"move","path":"active"}]}`, map[string]string{"id": created.ID})
			w := httptest.NewRecorder()
			require.NoError(t, srv.PatchUser(w, r))

			assert.Equal(t, http.StatusBadRequest, w.Code)
		})

		t.Run("DELETE removes a User and answers 204", func(t *testing.T) {
			srv := newServerFor("http://localhost:9999")
			created := create(t, srv, "eve")

			r := scimRequest(http.MethodDelete, "/Users/"+created.ID, "", map[string]string{"id": created.ID})
			w := httptest.NewRecorder()
			require.NoError(t, srv.DeleteUser(w, r))

			require.Equal(t, http.StatusNoContent, w.Code)
			assert.Empty(t, w.Body.String())

			get := scimRequest(http.MethodGet, "/Users/"+created.ID, "", map[string]string{"id": created.ID})
			gw := httptest.NewRecorder()
			require.NoError(t, srv.UserByID(gw, get))
			assert.Equal(t, http.StatusNotFound, gw.Code)
		})

		t.Run("DELETE of an unknown id is not found", func(t *testing.T) {
			srv := newServerFor("http://localhost:9999")
			id := uuid.Must(uuid.NewV4()).String()

			r := scimRequest(http.MethodDelete, "/Users/"+id, "", map[string]string{"id": id})
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

func scimRequest(method, target, body string, params map[string]string) *http.Request {
	r := httptest.NewRequest(method, BasePath+target, strings.NewReader(body))

	routeCtx := chi.NewRouteContext()
	for key, value := range params {
		routeCtx.URLParams.Add(key, value)
	}

	ctx := context.WithValue(r.Context(), chi.RouteCtxKey, routeCtx)
	return r.WithContext(withTenant(ctx, tenant))
}

func usersFor(t *testing.T, userNames ...string) (*Server, func(query string) *httptest.ResponseRecorder) {
	t.Helper()

	srv := newServerFor("http://localhost:9999")
	store, ok := srv.users.(*MemoryStore[*core.User])
	require.True(t, ok)

	for i, userName := range userNames {
		store.Put(tenant, &core.User{ID: strconv.Itoa(i), UserName: userName})
	}

	return srv, func(query string) *httptest.ResponseRecorder {
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

func userNamesOf(users []*core.User) []string {
	names := make([]string, 0, len(users))
	for _, user := range users {
		names = append(names, user.UserName)
	}
	return names
}
