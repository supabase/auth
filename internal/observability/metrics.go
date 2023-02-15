package observability

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/supabase/gotrue/internal/conf"

	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	metricglobal "go.opentelemetry.io/otel/metric/global"
	metricinstrument "go.opentelemetry.io/otel/metric/instrument"
	basicmetriccontroller "go.opentelemetry.io/otel/sdk/metric/controller/basic"
	exportmetricaggregation "go.opentelemetry.io/otel/sdk/metric/export/aggregation"
	basicmetricprocessor "go.opentelemetry.io/otel/sdk/metric/processor/basic"
	simplemetricselector "go.opentelemetry.io/otel/sdk/metric/selector/simple"

	otelruntimemetrics "go.opentelemetry.io/contrib/instrumentation/runtime"
)

func Meter(instrumentationName string, opts ...metric.MeterOption) metric.Meter {
	return metricglobal.Meter(instrumentationName, opts...)
}

func enablePrometheusMetrics(ctx context.Context, mc *conf.MetricsConfig) error {
	controller := basicmetriccontroller.New(
		basicmetricprocessor.NewFactory(
			simplemetricselector.NewWithHistogramDistribution(),
			exportmetricaggregation.CumulativeTemporalitySelector(),
			basicmetricprocessor.WithMemory(true), // pushes all metrics, not only the collected ones
		),
		basicmetriccontroller.WithResource(openTelemetryResource()),
	)

	exporter, err := prometheus.New(prometheus.Config{}, controller)
	if err != nil {
		return err
	}

	metricglobal.SetMeterProvider(exporter.MeterProvider())

	cleanupWaitGroup.Add(1)
	go func() {
		addr := net.JoinHostPort(mc.PrometheusListenHost, mc.PrometheusListenPort)
		baseContext, cancel := context.WithCancel(context.Background())

		server := &http.Server{
			Addr:    addr,
			Handler: exporter,
			BaseContext: func(net.Listener) context.Context {
				return baseContext
			},
			ReadHeaderTimeout: 2 * time.Second, // to mitigate a Slowloris attack
		}

		go func() {
			defer cleanupWaitGroup.Done()
			<-ctx.Done()

			cancel() // close baseContext

			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutdownCancel()

			if err := server.Shutdown(shutdownCtx); err != nil {
				logrus.WithError(err).Errorf("prometheus server (%s) failed to gracefully shut down", addr)
			}
		}()

		logrus.Infof("prometheus server listening on %s", addr)

		if err := server.ListenAndServe(); err != nil {
			logrus.WithError(err).Errorf("prometheus server (%s) shut down", addr)
		} else {
			logrus.Info("prometheus metric exporter shut down")
		}
	}()

	return nil
}

func enableOpenTelemetryMetrics(ctx context.Context, mc *conf.MetricsConfig) error {
	var (
		err            error
		metricExporter *otlpmetric.Exporter
	)

	switch mc.ExporterProtocol {
	case "grpc":
		metricExporter, err = otlpmetricgrpc.New(ctx)
		if err != nil {
			return err
		}

	case "http/protobuf":
		metricExporter, err = otlpmetrichttp.New(ctx)
		if err != nil {
			return err
		}

	default: // http/json for example
		return fmt.Errorf("unsupported OpenTelemetry exporter protocol %q", mc.ExporterProtocol)
	}

	controller := basicmetriccontroller.New(
		basicmetricprocessor.NewFactory(
			simplemetricselector.NewWithHistogramDistribution(),
			metricExporter,
		),
		basicmetriccontroller.WithExporter(metricExporter),
		basicmetriccontroller.WithResource(openTelemetryResource()),
	)

	metricglobal.SetMeterProvider(controller)

	cleanupWaitGroup.Add(1)
	go func() {
		defer cleanupWaitGroup.Done()

		<-ctx.Done()

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()

		if err := metricExporter.Shutdown(shutdownCtx); err != nil {
			logrus.WithError(err).Error("unable to gracefully shut down OpenTelemetry metric exporter")
		} else {
			logrus.Info("OpenTelemetry metric exporter shut down")
		}
	}()

	if err := controller.Start(ctx); err != nil {
		logrus.WithError(err).Error("unable to start pushing OpenTelemetry metrics")
	} else {
		logrus.Info("OpenTelemetry metrics exporter started")
	}

	return nil
}

var (
	metricsOnce *sync.Once = &sync.Once{}
)

func ConfigureMetrics(ctx context.Context, mc *conf.MetricsConfig) error {
	if ctx == nil {
		panic("context must not be nil")
	}

	var err error

	metricsOnce.Do(func() {
		if mc.Enabled {
			switch mc.Exporter {
			case conf.Prometheus:
				if err = enablePrometheusMetrics(ctx, mc); err != nil {
					logrus.WithError(err).Error("unable to start prometheus metrics exporter")
					return
				}

			case conf.OpenTelemetryMetrics:
				if err = enableOpenTelemetryMetrics(ctx, mc); err != nil {
					logrus.WithError(err).Error("unable to start OTLP metrics exporter")

					return
				}
			}
		}

		if err := otelruntimemetrics.Start(otelruntimemetrics.WithMinimumReadMemStatsInterval(time.Second)); err != nil {
			logrus.WithError(err).Error("unable to start OpenTelemetry Go runtime metrics collection")
		} else {
			logrus.Info("Go runtime metrics collection started")
		}

		meter := metricglobal.Meter("gotrue")
		running, err := meter.AsyncInt64().Gauge(
			"gotrue_running",
			metricinstrument.WithDescription("Whether GoTrue is running (always 1)"),
		)
		if err != nil {
			logrus.WithError(err).Error("unable to get gotrue.gotrue_running gague metric")
			return
		}

		if err := meter.RegisterCallback(
			[]metricinstrument.Asynchronous{
				running,
			},
			func(ctx context.Context) {
				running.Observe(ctx, 1)
			},
		); err != nil {
			logrus.WithError(err).Error("unable to register gotrue.running gague metric")
		}
	})

	return err
}
