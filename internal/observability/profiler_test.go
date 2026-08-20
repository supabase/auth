package observability

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
)

// freeLocalPort returns the string form of a free TCP port on 127.0.0.1.
// Used by tests that need to start a real listener (profiler, prometheus)
// without colliding with other services or other tests running in parallel.
func freeLocalPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	return strconv.Itoa(port)
}

func TestConfigureProfilerDisabled(t *testing.T) {
	require.NoError(t, ConfigureProfiler(context.Background(), &conf.ProfilerConfig{Enabled: false}))
}

func TestConfigureProfilerStartsAndShutsDown(t *testing.T) {
	// Start the profiler on a free localhost port and immediately cancel the
	// context; the cleanup goroutine should run server.Shutdown without
	// hanging the test. The function returns nil regardless of whether the
	// underlying listener bound successfully, so coverage focuses on the
	// synchronous setup path.
	ctx, cancel := context.WithCancel(context.Background())
	port := freeLocalPort(t)
	require.NoError(t, ConfigureProfiler(ctx, &conf.ProfilerConfig{
		Enabled: true,
		Host:    "127.0.0.1",
		Port:    port,
	}))
	cancel()
	// Give the cleanup goroutine a brief moment to run.
	time.Sleep(150 * time.Millisecond)
}

func TestProfilerHandlerServeHTTP(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		expectedStatus int
	}{
		{name: "pprof index", path: "/debug/pprof/", expectedStatus: http.StatusOK},
		{name: "pprof cmdline", path: "/debug/pprof/cmdline", expectedStatus: http.StatusOK},
		{name: "pprof symbol", path: "/debug/pprof/symbol", expectedStatus: http.StatusOK},
		{name: "pprof goroutine", path: "/debug/pprof/goroutine", expectedStatus: http.StatusOK},
		{name: "pprof heap", path: "/debug/pprof/heap", expectedStatus: http.StatusOK},
		{name: "pprof allocs", path: "/debug/pprof/allocs", expectedStatus: http.StatusOK},
		{name: "pprof threadcreate", path: "/debug/pprof/threadcreate", expectedStatus: http.StatusOK},
		{name: "pprof block", path: "/debug/pprof/block", expectedStatus: http.StatusOK},
		{name: "pprof mutex", path: "/debug/pprof/mutex", expectedStatus: http.StatusOK},
		{name: "unknown path returns 404", path: "/debug/pprof/unknown", expectedStatus: http.StatusNotFound},
		{name: "non-pprof path returns 404", path: "/something/else", expectedStatus: http.StatusNotFound},
	}

	handler := &ProfilerHandler{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			require.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}
