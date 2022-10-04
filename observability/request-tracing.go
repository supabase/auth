package observability

import (
	"net/http"

	"github.com/go-chi/chi"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
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

// RequestTracing returns an HTTP handler that traces all HTTP requests coming
// in. Supports Chi routers, so this should be one of the first middlewares on
// the router.
func RequestTracing() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			defer traceChiRoutesSafely(r)
			defer traceChiRouteURLParamsSafely(r)

			next.ServeHTTP(w, r)
		}

		return otelhttp.NewHandler(http.HandlerFunc(fn), "api")
	}
}
