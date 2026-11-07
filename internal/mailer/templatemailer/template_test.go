package templatemailer

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
)

func TestCacheGet(t *testing.T) {
	const (
		maxAge    = time.Minute * 10
		retryIval = time.Second * 10
		custom    = "custom template 123456"
	)

	type testServer struct {
		failing atomic.Bool
		hits    atomic.Int64
	}

	setup := func(t *testing.T) (*testServer, *Cache, *conf.GlobalConfiguration, func(time.Duration)) {
		srv := &testServer{}
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			srv.hits.Add(1)
			if srv.failing.Load() {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write([]byte("custom template {{ .Token }}"))
		}))
		t.Cleanup(ts.Close)

		cfg := &conf.GlobalConfiguration{}
		cfg.Mailer.Templates.Confirmation = ts.URL + "/confirmation.html"
		cfg.Mailer.TemplateMaxSize = 1_000_000
		cfg.Mailer.TemplateMaxAge = maxAge
		cfg.Mailer.TemplateRetryInterval = retryIval

		now := time.Now()
		tc := NewCache()
		tc.now = func() time.Time { return now }
		advance := func(d time.Duration) { now = now.Add(d) }
		return srv, tc, cfg, advance
	}

	get := func(t *testing.T, tc *Cache, cfg *conf.GlobalConfiguration) (string, bool) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
		defer cancel()

		ent, err := tc.get(ctx, cfg, ConfirmationTemplate)
		require.NoError(t, err)

		var buf bytes.Buffer
		_, body, err := ent.execute(&buf, map[string]any{"Token": "123456"})
		require.NoError(t, err)
		return body, ent.def
	}

	t.Run("CustomTemplateIsCachedForMaxAge", func(t *testing.T) {
		srv, tc, cfg, advance := setup(t)

		body, def := get(t, tc, cfg)
		require.False(t, def)
		require.Equal(t, custom, body)

		advance(maxAge - time.Second)
		body, def = get(t, tc, cfg)
		require.False(t, def)
		require.Equal(t, custom, body)
		require.Equal(t, int64(1), srv.hits.Load())

		advance(time.Second)
		get(t, tc, cfg)
		require.Equal(t, int64(2), srv.hits.Load())
	})

	t.Run("CustomTemplateIsKeptWhenReloadFails", func(t *testing.T) {
		srv, tc, cfg, advance := setup(t)

		get(t, tc, cfg)
		srv.failing.Store(true)

		advance(maxAge)
		body, def := get(t, tc, cfg)
		require.False(t, def)
		require.Equal(t, custom, body)
		require.Equal(t, int64(2), srv.hits.Load())

		// The failed reload is not retried before the retry interval.
		advance(retryIval - time.Second)
		body, def = get(t, tc, cfg)
		require.False(t, def)
		require.Equal(t, custom, body)
		require.Equal(t, int64(2), srv.hits.Load())

		advance(time.Second)
		body, def = get(t, tc, cfg)
		require.False(t, def)
		require.Equal(t, custom, body)
		require.Equal(t, int64(3), srv.hits.Load())
	})

	t.Run("DefaultFallbackIsRetriedAfterRetryInterval", func(t *testing.T) {
		srv, tc, cfg, advance := setup(t)
		srv.failing.Store(true)

		// Cold cache and the template endpoint is down: default template.
		body, def := get(t, tc, cfg)
		require.True(t, def)
		require.NotEqual(t, custom, body)
		require.Equal(t, int64(1), srv.hits.Load())

		// The fallback is not retried before the retry interval.
		advance(retryIval - time.Second)
		_, def = get(t, tc, cfg)
		require.True(t, def)
		require.Equal(t, int64(1), srv.hits.Load())

		// Still failing: the default template is kept and retried again later.
		advance(time.Second)
		_, def = get(t, tc, cfg)
		require.True(t, def)
		require.Equal(t, int64(2), srv.hits.Load())

		// The endpoint recovers well within TemplateMaxAge.
		srv.failing.Store(false)

		advance(retryIval - time.Second)
		_, def = get(t, tc, cfg)
		require.True(t, def)
		require.Equal(t, int64(2), srv.hits.Load())

		advance(time.Second)
		body, def = get(t, tc, cfg)
		require.False(t, def, "default template still served after the retry interval")
		require.Equal(t, custom, body)
		require.Equal(t, int64(3), srv.hits.Load())

		// From now on the custom template is cached for TemplateMaxAge.
		srv.failing.Store(true)
		advance(maxAge - time.Second)
		body, def = get(t, tc, cfg)
		require.False(t, def)
		require.Equal(t, custom, body)
		require.Equal(t, int64(3), srv.hits.Load())
	})

	// With TemplateReloadingEnabled the background reloader already retries
	// the default fallback on the same interval.
	t.Run("BackgroundReloadRetriesDefaultFallback", func(t *testing.T) {
		srv, tc, cfg, advance := setup(t)
		cfg.Mailer.TemplateReloadingEnabled = true
		cfg.Mailer.TemplateReloadingMaxIdle = time.Minute * 20
		srv.failing.Store(true)

		_, def := get(t, tc, cfg)
		require.True(t, def)

		srv.failing.Store(false)
		advance(retryIval)
		tc.Reload(context.Background(), cfg)

		body, def := get(t, tc, cfg)
		require.False(t, def)
		require.Equal(t, custom, body)
	})
}
