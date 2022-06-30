package api

import (
	"context"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.10.0"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/conf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

type TracerTestSuite struct {
	suite.Suite
	API    *API
	Config *conf.Configuration

	instanceID uuid.UUID
}

func TestTracer(t *testing.T) {
	api, config, instanceID, err := setupAPIForTestForInstance()
	require.NoError(t, err)

	ts := &TracerTestSuite{
		API:        api,
		Config:     config,
		instanceID: instanceID,
	}
	defer api.db.Close()

	suite.Run(t, ts)
}

func getAttribute(attributes []attribute.KeyValue, key attribute.Key) *attribute.Value {
	for _, value := range attributes {
		if value.Key == key {
			return &value.Value
		}
	}

	return nil
}

func (ts *TracerTestSuite) TestTracer_Spans() {
	exporter := tracetest.NewInMemoryExporter()
	bsp := sdktrace.NewBatchSpanProcessor(exporter)
	traceProvider := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithSpanProcessor(bsp),
	)
	otel.SetTracerProvider(traceProvider)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://localhost/something1", nil)
	ts.API.handler.ServeHTTP(w, req)
	req = httptest.NewRequest(http.MethodGet, "http://localhost/something2", nil)
	ts.API.handler.ServeHTTP(w, req)

	var spans []sdktrace.ReadOnlySpan
	err := exporter.ExportSpans(context.Background(), spans)
	isNilError := assert.Equal(ts.T(), nil, err)

	if isNilError && assert.Equal(ts.T(), 2, len(spans)) {
		attributes1 := spans[0].Attributes()
		method1 := getAttribute(attributes1, semconv.HTTPMethodKey)
		assert.Equal(ts.T(), "POST", method1.AsString())
		url1 := getAttribute(attributes1, semconv.HTTPURLKey)
		assert.Equal(ts.T(), "/something1", url1.AsString())
		statusCode1 := getAttribute(attributes1, semconv.HTTPStatusCodeKey)
		assert.Equal(ts.T(), "404", statusCode1.AsString())

		attributes2 := spans[0].Attributes()
		method2 := getAttribute(attributes2, semconv.HTTPMethodKey)
		assert.Equal(ts.T(), "GET", method2.AsString())
		url2 := getAttribute(attributes2, semconv.HTTPURLKey)
		assert.Equal(ts.T(), "/something2", url2.AsString())
		statusCode2 := getAttribute(attributes2, semconv.HTTPStatusCodeKey)
		assert.Equal(ts.T(), "404", statusCode2.AsString())
	}
}
