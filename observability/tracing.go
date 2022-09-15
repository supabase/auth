package observability

import (
	"net"
	"sync"

	"github.com/netlify/gotrue/conf"
	"github.com/opentracing/opentracing-go"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/opentracer"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
)

var (
	tracingOnce sync.Once
)

func ConfigureTracing(tc *conf.TracingConfig) error {
	tracingOnce.Do(func() {
		var t opentracing.Tracer = opentracing.NoopTracer{}

		if tc.Enabled {
			tracerOps := []tracer.StartOption{
				tracer.WithServiceName(tc.ServiceName),
				tracer.WithAgentAddr(net.JoinHostPort(tc.Host, tc.Port)),
			}

			for k, v := range tc.Tags {
				tracerOps = append(tracerOps, tracer.WithGlobalTag(k, v))
			}

			t = opentracer.New(tracerOps...)
		}

		opentracing.SetGlobalTracer(t)
	})

	return nil
}
