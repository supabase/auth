package scim

import (
	"context"
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
	"github.com/supabase-community/scim-go/pkg/server"
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

const validToken = "scim_valid"

func validateToken(ctx context.Context, candidate string) (context.Context, error) {
	if candidate != validToken {
		return ctx, server.ErrInvalidToken
	}
	return ctx, nil
}

func newServerFor(externalURL string) *Server {
	return NewServer(&conf.GlobalConfiguration{
		API: conf.APIConfiguration{ExternalURL: externalURL},
	}, validateToken, nil)
}

func serve(t *testing.T, srv *Server, method, path, body string, headers ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", protocol.MediaType)
	r.Header.Set("Authorization", "Bearer "+validToken)
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

	t.Run("requires a bearer token", func(t *testing.T) {
		for _, tc := range []struct {
			name, authorization string
			status              int
			challenge           string
		}{
			{"missing header", "", http.StatusUnauthorized, "Bearer"},
			{"wrong scheme", "Basic " + validToken, http.StatusUnauthorized, "Bearer"},
			{"empty token", "Bearer ", http.StatusBadRequest, `Bearer error="invalid_request", error_description="missing bearer token"`},
			{"invalid token", "Bearer scim_invalid", http.StatusUnauthorized, `Bearer error="invalid_token", error_description="The access token is invalid"`},
		} {
			t.Run(tc.name, func(t *testing.T) {
				w := serve(t, srv, http.MethodGet, BasePath+"/Users", "", "Authorization", tc.authorization)

				require.Equal(t, tc.status, w.Code)
				require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
				require.Equal(t, tc.challenge, w.Header().Get("WWW-Authenticate"))
			})
		}
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
