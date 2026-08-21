package scim

import (
	"context"
	"embed"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api/scim/core"
	"github.com/supabase/auth/internal/api/scim/protocol"
	"github.com/supabase/auth/internal/api/shared"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
)

//go:embed testdata/*
var fixtures embed.FS

func testFixture(t *testing.T, file string) string {
	data, err := fixtures.ReadFile("testdata/" + file)
	require.NoError(t, err)
	return string(data)
}

func newServerFor(externalURL string) *Server {
	return NewServer(&conf.GlobalConfiguration{
		API: conf.APIConfiguration{ExternalURL: externalURL},
	}, nil)
}

func TestServer(t *testing.T) {
	srv := newServerFor("http://localhost:9999")
	require.NotNil(t, srv)

	t.Run("NewServer trims a trailing slash from the external URL", func(t *testing.T) {
		location := newServerFor("https://auth.example.com/").serviceProviderConfig.Meta.Location

		require.Equal(t, "https://auth.example.com"+BasePath+"/ServiceProviderConfig", location)
	})

	t.Run("ServiceProviderConfig", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, BasePath+"/ServiceProviderConfig", nil)
		w := httptest.NewRecorder()

		require.NoError(t, srv.ServiceProviderConfig(w, r))

		require.Equal(t, http.StatusOK, w.Code)
		require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
		require.JSONEq(t, testFixture(t, "service_provider_config.json"), w.Body.String())
	})

	for _, tc := range []struct {
		path, fixture string
		id            string
		list, byID    func(http.ResponseWriter, *http.Request) error
	}{
		{"ResourceTypes", "resource_type_user.json", string(core.KindUser.Name), srv.ResourceTypes, srv.ResourceTypeByID},
		{"Schemas", "schema_user.json", string(core.SchemaUser), srv.Schemas, srv.SchemaByID},
	} {
		t.Run(tc.path, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, BasePath+"/"+tc.path, nil)
			w := httptest.NewRecorder()

			require.NoError(t, tc.list(w, r))

			require.Equal(t, http.StatusOK, w.Code)
			require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))

			var body protocol.ListResponse[json.RawMessage]
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))

			require.Equal(t, 1, body.TotalResults)
			require.Len(t, body.Resources, 1)
			require.JSONEq(t, testFixture(t, tc.fixture), string(body.Resources[0]))
		})

		t.Run(tc.path+" rejects filter query parameter", func(t *testing.T) {
			filter := url.Values{"filter": {`name eq "User"`}}.Encode()
			r := httptest.NewRequest(http.MethodGet, BasePath+"/"+tc.path+"?"+filter, nil)
			w := httptest.NewRecorder()

			require.NoError(t, tc.list(w, r))

			require.Equal(t, http.StatusForbidden, w.Code)
			require.JSONEq(t, testFixture(t, "filter_forbidden.json"), w.Body.String())
		})

		t.Run(tc.path+"/"+tc.id, func(t *testing.T) {
			r := requestWithURLParam(tc.path+"/"+tc.id, "id", tc.id)
			w := httptest.NewRecorder()

			require.NoError(t, tc.byID(w, r))

			require.Equal(t, http.StatusOK, w.Code)
			require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
			require.JSONEq(t, testFixture(t, tc.fixture), w.Body.String())
		})

		t.Run(tc.path+" returns a SCIM 404 for an unknown id", func(t *testing.T) {
			r := requestWithURLParam(tc.path+"/Unknown", "id", "Unknown")
			w := httptest.NewRecorder()

			require.NoError(t, tc.byID(w, r))

			require.Equal(t, http.StatusNotFound, w.Code)
			require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
			require.JSONEq(t, testFixture(t, "not_found.json"), w.Body.String())
		})
	}

	t.Run("NotFound", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, BasePath+"/Unknown", nil)
		w := httptest.NewRecorder()

		require.NoError(t, srv.NotFound(w, r))

		require.Equal(t, http.StatusNotFound, w.Code)
		require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
		require.JSONEq(t, testFixture(t, "not_found.json"), w.Body.String())
	})

	t.Run("Users rejects a filter it cannot honour", func(t *testing.T) {
		filter := url.Values{"filter": {`userName eq "user@example.com"`}}.Encode()
		r := httptest.NewRequest(http.MethodGet, BasePath+"/Users?"+filter, nil)
		w := httptest.NewRecorder()

		require.NoError(t, srv.Users(w, r))

		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
		require.JSONEq(t, testFixture(t, "filter_invalid.json"), w.Body.String())
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

// usersFor returns a server holding the given users for one tenant, and a
// request already carrying that tenant.
func usersFor(t *testing.T, userNames ...string) (*Server, func(query string) *httptest.ResponseRecorder) {
	t.Helper()

	srv := newServerFor("http://localhost:9999")
	repo, ok := srv.users.(*MemoryRepository[*core.User])
	require.True(t, ok)

	provider := &models.SSOProvider{ID: uuid.Must(uuid.NewV4())}
	for i, userName := range userNames {
		repo.Put(provider.ID.String(), &core.User{ID: strconv.Itoa(i), UserName: userName})
	}

	return srv, func(query string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, BasePath+"/Users?"+query, nil)
		r = r.WithContext(shared.WithSSOProvider(r.Context(), provider))

		w := httptest.NewRecorder()
		require.NoError(t, srv.Users(w, r))
		return w
	}
}

func listedUsers(t *testing.T, w *httptest.ResponseRecorder) protocol.ListResponse[*core.User] {
	t.Helper()

	var body protocol.ListResponse[*core.User]
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	return body
}

func TestServerUsers(t *testing.T) {
	t.Run("counts every match, not the resources on the page", func(t *testing.T) {
		_, get := usersFor(t, "a", "b", "c", "d", "e")

		w := get("startIndex=2&count=2")
		body := listedUsers(t, w)

		require.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, 5, body.TotalResults)
		assert.Equal(t, 2, body.StartIndex)
		assert.Equal(t, 2, body.ItemsPerPage)
		assert.Len(t, body.Resources, 2)
	})

	t.Run("answers a count of none with the total alone", func(t *testing.T) {
		_, get := usersFor(t, "a", "b", "c")

		w := get("count=0")
		body := listedUsers(t, w)

		require.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, 3, body.TotalResults)
		assert.Equal(t, 0, body.ItemsPerPage)
		assert.Empty(t, body.Resources)
		assert.Contains(t, w.Body.String(), `"Resources":[]`)
	})

	t.Run("sorts by the attribute the client names", func(t *testing.T) {
		_, get := usersFor(t, "carol", "alice", "bob")

		ascending := listedUsers(t, get("sortBy=userName"))
		descending := listedUsers(t, get("sortBy=userName&sortOrder=descending"))

		assert.Equal(t, []string{"alice", "bob", "carol"}, userNamesOf(ascending.Resources))
		assert.Equal(t, []string{"carol", "bob", "alice"}, userNamesOf(descending.Resources))
	})

	t.Run("refuses an attribute it cannot sort by", func(t *testing.T) {
		_, get := usersFor(t, "a")

		w := get("sortBy=nickName")

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
		assert.Contains(t, w.Body.String(), string(protocol.ScimTypeInvalidValue))
		assert.Contains(t, w.Body.String(), "nickName")
	})

	t.Run("refuses an order that is neither ascending nor descending", func(t *testing.T) {
		_, get := usersFor(t, "a")

		w := get("sortBy=userName&sortOrder=sideways")

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), string(protocol.ScimTypeInvalidValue))
	})
}

func userNamesOf(users []*core.User) []string {
	names := make([]string, 0, len(users))
	for _, user := range users {
		names = append(names, user.UserName)
	}
	return names
}
