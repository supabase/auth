package observability

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	semconv "go.opentelemetry.io/otel/semconv/v1.38.0"
)

func TestRequestTracing(t *testing.T) {
	spans := tracetest.NewSpanRecorder()
	reader := sdkmetric.NewManualReader()

	prevTracerProvider, prevMeterProvider := otel.GetTracerProvider(), otel.GetMeterProvider()
	otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spans)))
	otel.SetMeterProvider(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	t.Cleanup(func() {
		otel.SetTracerProvider(prevTracerProvider)
		otel.SetMeterProvider(prevMeterProvider)
	})

	router := chi.NewRouter()
	router.Use(RequestTracing())
	// like the API's later middlewares, copy the request so otelhttp never sees chi's r.Pattern
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(r.Context()))
		})
	})
	router.Get("/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/users/123", nil))
	require.Equal(t, http.StatusOK, w.Code)

	ended := spans.Ended()
	require.Len(t, ended, 1)
	require.Equal(t, "api", ended[0].Name())

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))

	var duration *metricdata.Histogram[float64]
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == "http.server.request.duration" {
				h := m.Data.(metricdata.Histogram[float64])
				duration = &h
			}
		}
	}
	require.NotNil(t, duration, "http.server.request.duration not recorded")
	require.Len(t, duration.DataPoints, 1)

	route, ok := duration.DataPoints[0].Attributes.Value(semconv.HTTPRouteKey)
	require.True(t, ok, "http.route attribute missing")
	require.Equal(t, "/users/{id}", route.AsString())
}
