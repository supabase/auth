package conf

import (
	"encoding/json"
	"fmt"
)

type TracingExporter = string

const (
	OpenTelemetryTracing TracingExporter = "opentelemetry"
)

type TracingConfig struct {
	Enabled  bool
	Exporter TracingExporter `default:"opentelemetry"`

	// ExporterProtocol is the OTEL_EXPORTER_OTLP_PROTOCOL env variable,
	// only available when exporter is opentelemetry. See:
	// https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/protocol/exporter.md
	ExporterProtocol string `default:"http/protobuf" envconfig:"OTEL_EXPORTER_OTLP_PROTOCOL"`

	// Host is the host of the OpenTracing collector.
	Host string

	// Port is the port of the OpenTracing collector.
	Port string

	// ServiceName is the service name to use with OpenTracing.
	ServiceName string `default:"gotrue" split_words:"true"`

	Headers TracingHeaderDecoder

	// Tags are the tags to associate with OpenTracing.
	Tags map[string]string
}

func (tc *TracingConfig) Validate() error {
	return nil
}

type TracingHeaderDecoder map[string]string

func (h *TracingHeaderDecoder) Decode(value string) error {
	headers := make(TracingHeaderDecoder)
	if value != "" {
		if err := json.Unmarshal([]byte(value), &headers); err != nil {
			return fmt.Errorf("conf: custom headers not a map[string][]string: %w", err)
		}
	}
	*h = headers
	return nil
}
