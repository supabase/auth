package observability

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
)

func TestGetChiRoutePatternNoRouteContext(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/anything", nil)
	require.Equal(t, "noroute", getChiRoutePattern(req))
}

func TestGetChiRoutePatternWithRouter(t *testing.T) {
	r := chi.NewRouter()
	var captured string
	r.Get("/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		captured = getChiRoutePattern(r)
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/users/42", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "/users/{id}", captured)
}

func TestTraceChiRoutesSafelyDoesNotPanicWithoutRouteContext(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/no/route/context", nil)
	require.NotPanics(t, func() { traceChiRoutesSafely(req) })
}

func TestTraceChiRouteURLParamsSafelyDoesNotPanicWithoutRouteContext(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/no/route/context", nil)
	require.NotPanics(t, func() { traceChiRouteURLParamsSafely(req) })
}

func TestAddMetricAttributesIncludesRoutePattern(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/something", nil)
	attrs := addMetricAttributes(req)
	require.NotEmpty(t, attrs)
	// The first attribute should be the route key. Without a chi RouteContext
	// the value falls back to "noroute".
	require.Equal(t, "noroute", attrs[0].Value.AsString())
}

func TestInterceptingResponseWriterDelegates(t *testing.T) {
	inner := httptest.NewRecorder()
	w := &interceptingResponseWriter{writer: inner}

	w.Header().Set("X-Test", "value")
	require.Equal(t, "value", inner.Header().Get("X-Test"))

	w.WriteHeader(http.StatusTeapot)
	require.Equal(t, http.StatusTeapot, inner.Code)
	require.Equal(t, http.StatusTeapot, w.statusCode)

	n, err := w.Write([]byte("hello"))
	require.NoError(t, err)
	require.Equal(t, 5, n)
	require.Equal(t, "hello", inner.Body.String())
}

func TestCountStatusCodesSafelyNilCounterIsNoop(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/path", nil)
	writer := &interceptingResponseWriter{statusCode: http.StatusOK}
	require.NotPanics(t, func() { countStatusCodesSafely(writer, req, nil) })
}

func TestTraceChiRoutesSafelyWithRouteContext(t *testing.T) {
	r := chi.NewRouter()
	r.Get("/items/{id}", func(w http.ResponseWriter, r *http.Request) {
		require.NotPanics(t, func() { traceChiRoutesSafely(r) })
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/items/42", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestTraceChiRouteURLParamsSafelyWithRouteContext(t *testing.T) {
	r := chi.NewRouter()
	r.Get("/orgs/{org}/items/{id}", func(w http.ResponseWriter, r *http.Request) {
		require.NotPanics(t, func() { traceChiRouteURLParamsSafely(r) })
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/orgs/acme/items/7", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestCountStatusCodesSafelyWithRealCounter(t *testing.T) {
	counter, err := otel.Meter("gotrue-test").Int64Counter("test_status_codes")
	require.NoError(t, err)

	r := chi.NewRouter()
	r.Get("/items/{id}", func(w http.ResponseWriter, r *http.Request) {
		writer := &interceptingResponseWriter{statusCode: http.StatusOK}
		require.NotPanics(t, func() { countStatusCodesSafely(writer, r, counter) })
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/items/1", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestRequestTracingMiddlewareInvokesNext(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := RequestTracing()(next)
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	req.Header.Set("User-Agent", "agent-under-test")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	require.True(t, called, "next handler should have been invoked")
	require.Equal(t, http.StatusOK, w.Code)
}
