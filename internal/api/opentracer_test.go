package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/mocktracer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/gotrue/internal/conf"
	"github.com/supabase/gotrue/internal/storage"
)

type OpenTracerTestSuite struct {
	suite.Suite
	API    *API
	Config *conf.GlobalConfiguration
}

func TestOpenTracer(t *testing.T) {
	api, config, err := setupAPIForTestWithCallback(func(config *conf.GlobalConfiguration, conn *storage.Connection) {
		if config != nil {
			config.Tracing.Enabled = true
			config.Tracing.Exporter = conf.OpenTracing
		}
	})

	require.NoError(t, err)

	ts := &OpenTracerTestSuite{
		API:    api,
		Config: config,
	}
	defer api.db.Close()

	suite.Run(t, ts)
}

func (ts *OpenTracerTestSuite) TestOpenTracer_Spans() {
	mt := mocktracer.New()
	opentracing.SetGlobalTracer(mt)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://localhost/something1", nil)
	ts.API.handler.ServeHTTP(w, req)
	req = httptest.NewRequest(http.MethodGet, "http://localhost/something2", nil)
	ts.API.handler.ServeHTTP(w, req)

	spans := mt.FinishedSpans()
	if assert.Equal(ts.T(), 2, len(spans)) {
		assert.Equal(ts.T(), "POST", spans[0].Tag("http.method"))
		assert.Equal(ts.T(), "/something1", spans[0].Tag("http.url"))
		assert.Equal(ts.T(), "POST /something1", spans[0].Tag("resource.name"))
		assert.Equal(ts.T(), "404", spans[0].Tag("http.status_code"))
		assert.NotEmpty(ts.T(), spans[0].Tag("http.request_id"))

		assert.Equal(ts.T(), "GET", spans[1].Tag("http.method"))
		assert.Equal(ts.T(), "/something2", spans[1].Tag("http.url"))
		assert.Equal(ts.T(), "GET /something2", spans[1].Tag("resource.name"))
		assert.Equal(ts.T(), "404", spans[1].Tag("http.status_code"))
		assert.NotEmpty(ts.T(), spans[1].Tag("http.request_id"))
	}
}
