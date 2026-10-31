package observability

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
)

func TestTracer(t *testing.T) {
	require.NotNil(t, Tracer("test-tracer"))
}

func TestOpenTelemetryResource(t *testing.T) {
	resource := openTelemetryResource()
	require.NotNil(t, resource)
	// The resource should at minimum carry the gotrue.version attribute that
	// openTelemetryResource merges in. We don't assert the exact value because
	// utilities.Version is a build-time string; presence is enough.
	require.NotEmpty(t, resource.Attributes())
}

func TestConfigureTracingNilContextPanics(t *testing.T) {
	require.PanicsWithValue(t, "context must not be nil", func() {
		_ = ConfigureTracing(nil, &conf.TracingConfig{})
	})
}

func TestConfigureTracingDisabled(t *testing.T) {
	require.NoError(t, ConfigureTracing(context.Background(), &conf.TracingConfig{Enabled: false}))
}

func TestEnableOpenTelemetryTracingRejectsUnsupportedExporter(t *testing.T) {
	err := enableOpenTelemetryTracing(context.Background(), &conf.TracingConfig{ExporterProtocol: "http/json"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported OpenTelemetry exporter protocol")
}

func TestEnableOpenTelemetryTracingGRPC(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	require.NoError(t, enableOpenTelemetryTracing(ctx, &conf.TracingConfig{ExporterProtocol: "grpc"}))
	cancel()
	time.Sleep(150 * time.Millisecond)
}

func TestEnableOpenTelemetryTracingHTTPProtobuf(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	require.NoError(t, enableOpenTelemetryTracing(ctx, &conf.TracingConfig{ExporterProtocol: "http/protobuf"}))
	cancel()
	time.Sleep(150 * time.Millisecond)
}
