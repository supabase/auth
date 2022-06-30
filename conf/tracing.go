package conf

import (
	"context"
	"fmt"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric/global"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/metric/controller/basic"
	controller "go.opentelemetry.io/otel/sdk/metric/controller/basic"
	"go.opentelemetry.io/otel/sdk/metric/selector/simple"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.10.0"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"net/http"
	"time"

	processor "go.opentelemetry.io/otel/sdk/metric/processor/basic"
)

type Exporter = string

const (
	DatadogExporter    Exporter = "datadog"
	OtlpGrpcExporter   Exporter = "otlpgrpc"
	OtlpHttpExporter   Exporter = "otlphttp"
	PrometheusExporter Exporter = "prometheus"
)

type TracingConfig struct {
	Enabled     bool     `default:"false"`
	Host        string   `default:"127.0.0.1"`
	Port        string   `default:"2222"`
	Exporter    Exporter `default:"datadog"`
	ServiceName string   `default:"gotrue" split_words:"true"`
	Tags        map[string]string

	// INTERNAL, used to start in `api.go`
	OtlpMetricExporter *otlpmetric.Exporter            `ignore:"true"`
	TracingShutdown    func(ctx context.Context) error `ignore:"true"`
	ContextCancel      func()                          `ignore:"true"`
}

func (tc *TracingConfig) tracingAddr() string {
	return fmt.Sprintf("%s:%s", tc.Host, tc.Port)
}

func ConfigureTracing(tc *TracingConfig) {
	if tc.Enabled {
		var t trace.TracerProvider
		var c *controller.Controller

		switch tc.Exporter {
		case OtlpGrpcExporter:
		case DatadogExporter:
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			tc.ContextCancel = cancel
			conn, err := grpc.DialContext(ctx, tc.tracingAddr(), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
			if err != nil {
				panic(fmt.Errorf("failed to create gRPC connection to collector: %w", err))
			}
			otlpMetrics, err := otlpmetricgrpc.New(ctx, otlpmetricgrpc.WithGRPCConn(conn))
			if err != nil {
				panic(fmt.Errorf("failed to start grpc metrics: %w", err))
			}
			otlpTracing, err := otlptracegrpc.New(ctx, otlptracegrpc.WithGRPCConn(conn))
			if err != nil {
				panic(fmt.Errorf("failed to start grpc tracing: %w", err))
			}

			// Setup Metrics
			tc.OtlpMetricExporter = otlpMetrics
			c = controller.New(
				processor.NewFactory(
					simple.NewWithHistogramDistribution(),
					otlpMetrics,
				),
				controller.WithExporter(otlpMetrics),
				controller.WithCollectPeriod(2*time.Second),
			)

			// Setup Tracing
			res, err := resource.New(
				ctx,
				resource.WithAttributes(
					// the service name used to display traces in backends
					semconv.ServiceNameKey.String(tc.ServiceName),
				),
			)
			if err != nil {
				panic(fmt.Errorf("failed to create resource: %w", err))
			}

			bsp := sdktrace.NewBatchSpanProcessor(otlpTracing)
			traceProvider := sdktrace.NewTracerProvider(
				sdktrace.WithSampler(sdktrace.AlwaysSample()),
				sdktrace.WithResource(res),
				sdktrace.WithSpanProcessor(bsp),
			)
			t = traceProvider
			otel.SetTextMapPropagator(propagation.TraceContext{})
			tc.TracingShutdown = traceProvider.Shutdown

		case OtlpHttpExporter:
			ctx := context.Background()
			otlpMetrics, err := otlpmetrichttp.New(ctx)
			if err != nil {
				panic(fmt.Errorf("failed to start http metrics: %w", err))
			}
			otlpTracing, err := otlptracehttp.New(ctx)
			if err != nil {
				panic(fmt.Errorf("failed to start http tracing: %w", err))
			}

			// Setup Metrics
			tc.OtlpMetricExporter = otlpMetrics
			c = controller.New(
				processor.NewFactory(
					simple.NewWithHistogramDistribution(),
					otlpMetrics,
				),
				controller.WithExporter(otlpMetrics),
				controller.WithCollectPeriod(2*time.Second),
			)

			// Setup Tracing
			res, err := resource.New(
				ctx,
				resource.WithAttributes(
					// the service name used to display traces in backends
					semconv.ServiceNameKey.String(tc.ServiceName),
				),
			)
			if err != nil {
				panic(fmt.Errorf("failed to create resource: %w", err))
			}

			bsp := sdktrace.NewBatchSpanProcessor(otlpTracing)
			traceProvider := sdktrace.NewTracerProvider(
				sdktrace.WithSampler(sdktrace.AlwaysSample()),
				sdktrace.WithResource(res),
				sdktrace.WithSpanProcessor(bsp),
			)
			t = traceProvider
			otel.SetTextMapPropagator(propagation.TraceContext{})
			tc.TracingShutdown = traceProvider.Shutdown
		//! Doesn't support traces!
		case PrometheusExporter:
			p, err := prometheus.New(prometheus.Config{}, &basic.Controller{})
			if err != nil {
				panic(fmt.Errorf("failed to create prometheus exporter: %w", err))
			}

			pServerMux := http.NewServeMux()
			pServerMux.HandleFunc("/", p.ServeHTTP)
			go func() {
				logrus.StandardLogger().Info(fmt.Sprintf("Prometheus started, listening at %s", tc.tracingAddr()))
				_ = http.ListenAndServe(tc.tracingAddr(), pServerMux)
			}()
			c = p.Controller()
		}

		otel.SetTracerProvider(t)
		global.SetMeterProvider(c)
	} else {
		t := trace.NewNoopTracerProvider()
		otel.SetTracerProvider(t)
	}
}
