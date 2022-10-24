package observability

import (
	"context"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	metricglobal "go.opentelemetry.io/otel/metric/global"
	metricinstrument "go.opentelemetry.io/otel/metric/instrument"
	semconv "go.opentelemetry.io/otel/semconv/v1.12.0"
	"go.opentelemetry.io/otel/trace"
)

// traceChiRoutesSafely attempts to extract the Chi RouteContext. If the
// request does not have a RouteContext it will recover from the panic and
// attempt to figure out the route from the URL's path.
func traceChiRoutesSafely(r *http.Request) {
	defer func() {
		if rec := recover(); rec != nil {
			logrus.WithField("error", rec).Error("unable to trace chi routes, traces may be off")

			span := trace.SpanFromContext(r.Context())
			span.SetAttributes(semconv.HTTPRouteKey.String(r.URL.Path))
		}
	}()

	routeContext := chi.RouteContext(r.Context())
	span := trace.SpanFromContext(r.Context())
	span.SetAttributes(semconv.HTTPRouteKey.String(routeContext.RoutePattern()))
}

// traceChiRouteURLParamsSafely attempts to extract the Chi RouteContext
// URLParams values for the route and assign them to the tracing span. If the
// request does not have a RouteContext it will recover from the panic and not
// set any params.
func traceChiRouteURLParamsSafely(r *http.Request) {
	defer func() {
		if rec := recover(); rec != nil {
			logrus.WithField("error", rec).Error("unable to trace route with route params, traces may be off")
		}
	}()

	routeContext := chi.RouteContext(r.Context())
	span := trace.SpanFromContext(r.Context())

	var attributes []attribute.KeyValue

	for i := 0; i < len(routeContext.URLParams.Keys); i += 1 {
		key := routeContext.URLParams.Keys[i]
		value := routeContext.URLParams.Values[i]

		attributes = append(attributes, attribute.String("http.route.param."+key, value))
	}

	if len(attributes) > 0 {
		span.SetAttributes(attributes...)
	}
}

type interceptingResponseWriter struct {
	writer http.ResponseWriter

	statusCode int
}

func (w *interceptingResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode

	w.writer.WriteHeader(statusCode)
}

func (w *interceptingResponseWriter) Write(data []byte) (int, error) {
	return w.writer.Write(data)
}

func (w *interceptingResponseWriter) Header() http.Header {
	return w.writer.Header()
}

type metricCounter interface {
	Add(ctx context.Context, incr int64, attrs ...attribute.KeyValue)
}

// countStatusCodesSafely counts the number of HTTP status codes per route that
// occurred while GoTrue was running. If it is not able to identify the route
// via chi.RouteContext(ctx).RoutePattern() it counts with a noroute attribute.
func countStatusCodesSafely(w *interceptingResponseWriter, r *http.Request, counter metricCounter) {
	if counter == nil {
		return
	}

	defer func() {
		if rec := recover(); rec != nil {
			logrus.WithField("error", rec).Error("unable to count status codes safely, metrics may be off")

			counter.Add(
				r.Context(),
				1,
				attribute.Bool("noroute", true),
				attribute.Int("code", w.statusCode),
			)
		}
	}()

	ctx := r.Context()

	routeContext := chi.RouteContext(ctx)
	routePattern := semconv.HTTPRouteKey.String(routeContext.RoutePattern())

	counter.Add(
		ctx,
		1,
		attribute.Int("code", w.statusCode),
		routePattern,
	)
}

// RequestTracing returns an HTTP handler that traces all HTTP requests coming
// in. Supports Chi routers, so this should be one of the first middlewares on
// the router.
func RequestTracing() func(http.Handler) http.Handler {
	meter := metricglobal.Meter("gotrue")
	statusCodes, err := meter.SyncInt64().Counter(
		"http_status_codes",
		metricinstrument.WithDescription("Number of returned HTTP status codes"),
	)
	if err != nil {
		logrus.WithError(err).Error("unable to get gotrue.http_status_codes counter metric")
	}

	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			writer := interceptingResponseWriter{
				writer: w,
			}

			defer traceChiRoutesSafely(r)
			defer traceChiRouteURLParamsSafely(r)
			defer countStatusCodesSafely(&writer, r, statusCodes)

			next.ServeHTTP(&writer, r)
		}

		return otelhttp.NewHandler(http.HandlerFunc(fn), "api")
	}
}
