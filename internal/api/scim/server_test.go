package scim

import (
	"embed"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/observability"
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
	})
}

func serve(t *testing.T, srv *Server, method, path, body string, headers ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", protocol.MediaType)
	for i := 0; i+1 < len(headers); i += 2 {
		r.Header.Set(headers[i], headers[i+1])
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	return w
}

func decode(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	return body
}

func TestServer(t *testing.T) {
	srv := newServerFor("http://localhost:9999")
	require.NotNil(t, srv)

	t.Run("NewServer trims a trailing slash from the external URL", func(t *testing.T) {
		w := serve(t, newServerFor("https://auth.example.com/"), http.MethodGet, BasePath+"/ServiceProviderConfig", "")

		meta := decode(t, w)["meta"].(map[string]any)
		require.Equal(t, "https://auth.example.com"+BasePath+"/ServiceProviderConfig", meta["location"])
	})

	t.Run("ServiceProviderConfig", func(t *testing.T) {
		w := serve(t, srv, http.MethodGet, BasePath+"/ServiceProviderConfig", "")

		require.Equal(t, http.StatusOK, w.Code)
		require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
		require.JSONEq(t, testFixture(t, "service_provider_config.json"), w.Body.String())
	})

	t.Run("ResourceTypes", func(t *testing.T) {
		w := serve(t, srv, http.MethodGet, BasePath+"/ResourceTypes", "")

		require.Equal(t, http.StatusOK, w.Code)
		require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
		body := decode(t, w)
		require.EqualValues(t, 1, body["totalResults"])
		resource := body["Resources"].([]any)[0].(map[string]any)
		require.Equal(t, "User", resource["id"])
		require.Equal(t, BasePath+"/Users", resource["endpoint"])
		require.Equal(t, string(core.SchemaUser), resource["schema"])
	})

	t.Run("ResourceTypes/User", func(t *testing.T) {
		w := serve(t, srv, http.MethodGet, BasePath+"/ResourceTypes/User", "")

		require.Equal(t, http.StatusOK, w.Code)
		require.Equal(t, "User", decode(t, w)["id"])
	})

	t.Run("Schemas", func(t *testing.T) {
		w := serve(t, srv, http.MethodGet, BasePath+"/Schemas", "")

		require.Equal(t, http.StatusOK, w.Code)
		require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
		body := decode(t, w)
		require.EqualValues(t, 1, body["totalResults"])
		require.Equal(t, string(core.SchemaUser), body["Resources"].([]any)[0].(map[string]any)["id"])
	})

	t.Run("Schemas/{id}", func(t *testing.T) {
		w := serve(t, srv, http.MethodGet, BasePath+"/Schemas/"+string(core.SchemaUser), "")

		require.Equal(t, http.StatusOK, w.Code)
		require.Equal(t, string(core.SchemaUser), decode(t, w)["id"])
	})

	for _, path := range []string{"/ResourceTypes", "/Schemas"} {
		t.Run(path+" rejects filter query parameter", func(t *testing.T) {
			filter := url.Values{"filter": {`name eq "User"`}}.Encode()
			w := serve(t, srv, http.MethodGet, BasePath+path+"?"+filter, "")

			require.Equal(t, http.StatusForbidden, w.Code)
			require.JSONEq(t, testFixture(t, "filter_forbidden.json"), w.Body.String())
		})
	}

	t.Run("Users", func(t *testing.T) {
		srv := newServerFor("http://localhost:9999")

		w := serve(t, srv, http.MethodPost, BasePath+"/Users", `{
			"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
			"userName": "alice@example.com",
			"name": {"givenName": "Alice", "familyName": "Smith"},
			"emails": [{"value": "alice@example.com", "type": "work", "primary": true}],
			"active": true
		}`)
		require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
		created := decode(t, w)
		id := created["id"].(string)
		require.NotEmpty(t, id)
		require.Equal(t, "alice@example.com", created["userName"])
		require.Equal(t, BasePath+"/Users/"+id, w.Header().Get("Location"))
		require.NotEmpty(t, w.Header().Get("ETag"))

		t.Run("rejects a duplicate userName", func(t *testing.T) {
			w := serve(t, srv, http.MethodPost, BasePath+"/Users", `{
				"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
				"userName": "alice@example.com"
			}`)
			require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
		})

		t.Run("get", func(t *testing.T) {
			w := serve(t, srv, http.MethodGet, BasePath+"/Users/"+id, "")
			require.Equal(t, http.StatusOK, w.Code)
			require.Equal(t, "alice@example.com", decode(t, w)["userName"])
		})

		t.Run("list with filter", func(t *testing.T) {
			filter := url.Values{"filter": {`userName eq "alice@example.com"`}}.Encode()
			w := serve(t, srv, http.MethodGet, BasePath+"/Users?"+filter, "")
			require.Equal(t, http.StatusOK, w.Code, w.Body.String())
			require.EqualValues(t, 1, decode(t, w)["totalResults"])
		})

		t.Run("replace", func(t *testing.T) {
			w := serve(t, srv, http.MethodPut, BasePath+"/Users/"+id, `{
				"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
				"userName": "alice@example.com",
				"name": {"givenName": "Alicia", "familyName": "Smith"}
			}`)
			require.Equal(t, http.StatusOK, w.Code, w.Body.String())
			require.Equal(t, "Alicia", decode(t, w)["name"].(map[string]any)["givenName"])
		})

		t.Run("patch", func(t *testing.T) {
			w := serve(t, srv, http.MethodPatch, BasePath+"/Users/"+id, `{
				"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				"Operations": [{"op": "replace", "path": "active", "value": false}]
			}`)
			require.Equal(t, http.StatusOK, w.Code, w.Body.String())
			require.Equal(t, false, decode(t, w)["active"])
		})

		t.Run("delete with a stale version", func(t *testing.T) {
			w := serve(t, srv, http.MethodDelete, BasePath+"/Users/"+id, "", "If-Match", `W/"stale"`)
			require.Equal(t, http.StatusPreconditionFailed, w.Code, w.Body.String())
		})

		t.Run("delete", func(t *testing.T) {
			w := serve(t, srv, http.MethodDelete, BasePath+"/Users/"+id, "")
			require.Equal(t, http.StatusNoContent, w.Code, w.Body.String())

			w = serve(t, srv, http.MethodGet, BasePath+"/Users/"+id, "")
			require.Equal(t, http.StatusNotFound, w.Code)
		})
	})

	t.Run("logError logs through the request log entry", func(t *testing.T) {
		logger, hook := logrustest.NewNullLogger()
		r := httptest.NewRequest(http.MethodGet, BasePath+"/Users", nil)
		entry := observability.NewLogEntry(logger.WithField("request_id", "req-1"))
		r = r.WithContext(observability.SetLogEntryWithContext(r.Context(), entry))

		logError(r, errors.New("broken pipe"))

		require.Len(t, hook.Entries, 1)
		require.Equal(t, logrus.ErrorLevel, hook.LastEntry().Level)
		require.Equal(t, "req-1", hook.LastEntry().Data["request_id"])
		require.EqualError(t, hook.LastEntry().Data[logrus.ErrorKey].(error), "broken pipe")
	})

	t.Run("NotFound", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, BasePath+"/Unknown", nil)
		w := httptest.NewRecorder()

		require.NoError(t, srv.NotFound(w, r))

		require.Equal(t, http.StatusNotFound, w.Code)
		require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
		require.JSONEq(t, testFixture(t, "not_found.json"), w.Body.String())
	})
}
