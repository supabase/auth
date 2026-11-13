package observability

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
)

func TestMeter(t *testing.T) {
	require.NotNil(t, Meter("test-meter"))
}

func TestObtainMetricCounter(t *testing.T) {
	require.NotNil(t, ObtainMetricCounter("test_counter", "a counter for tests"))
}

func TestConfigureMetricsNilContextPanics(t *testing.T) {
	require.PanicsWithValue(t, "context must not be nil", func() {
		_ = ConfigureMetrics(nil, &conf.MetricsConfig{})
	})
}

func TestConfigureMetricsDisabled(t *testing.T) {
	// metricsOnce is a package-level *sync.Once used to ensure ConfigureMetrics
	// runs exactly once per process. Reset it for this isolated test so we can
	// exercise the disabled-config branch without coupling to other tests.
	metricsOnce = &sync.Once{}
	require.NoError(t, ConfigureMetrics(context.Background(), &conf.MetricsConfig{Enabled: false}))
}

func TestEnableOpenTelemetryMetricsRejectsUnsupportedExporter(t *testing.T) {
	err := enableOpenTelemetryMetrics(context.Background(), &conf.MetricsConfig{ExporterProtocol: "http/json"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported OpenTelemetry exporter protocol")
}

func TestEnablePrometheusMetricsStartsAndShutsDown(t *testing.T) {
	// Coverage of the synchronous setup path; the goroutine that calls
	// ListenAndServe shuts down when the context is cancelled. The function
	// returns nil whether or not the listener binds, so we only assert the
	// happy synchronous outcome.
	ctx, cancel := context.WithCancel(context.Background())
	port := freeLocalPort(t)
	require.NoError(t, enablePrometheusMetrics(ctx, &conf.MetricsConfig{
		PrometheusListenHost: "127.0.0.1",
		PrometheusListenPort: port,
	}))
	cancel()
	time.Sleep(150 * time.Millisecond)
}

func TestEnableOpenTelemetryMetricsGRPC(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	require.NoError(t, enableOpenTelemetryMetrics(ctx, &conf.MetricsConfig{ExporterProtocol: "grpc"}))
	cancel()
	time.Sleep(150 * time.Millisecond)
}

func TestEnableOpenTelemetryMetricsHTTPProtobuf(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	require.NoError(t, enableOpenTelemetryMetrics(ctx, &conf.MetricsConfig{ExporterProtocol: "http/protobuf"}))
	cancel()
	time.Sleep(150 * time.Millisecond)
}
