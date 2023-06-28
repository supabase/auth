package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/supabase/gotrue/internal/conf"
	"github.com/supabase/gotrue/internal/models"
	"github.com/supabase/gotrue/internal/storage/test"
)

// withFunctionHooks adds the provided function hooks to the context.
func withFunctionHooks(ctx context.Context, hooks map[string][]string) context.Context {
	return context.WithValue(ctx, functionHooksKey, hooks)
}

func TestSignupHookSendInstanceID(t *testing.T) {
	globalConfig, err := conf.LoadGlobal(apiTestConfig)
	require.NoError(t, err)

	conn, err := test.SetupDBConnection(globalConfig)
	require.NoError(t, err)

	user, err := models.NewUser("81234567", "test@truth.com", "thisisapassword", "", nil)
	require.NoError(t, err)

	var callCount int
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		defer squash(r.Body.Close)
		raw, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		data := map[string]interface{}{}
		require.NoError(t, json.Unmarshal(raw, &data))

		assert.Len(t, data, 3)
		w.WriteHeader(http.StatusOK)
	}))
	defer svr.Close()

	config := &conf.GlobalConfiguration{
		Webhook: conf.WebhookConfig{
			URL:    svr.URL,
			Events: []string{SignupEvent},
		},
	}

	require.NoError(t, triggerEventHooks(context.Background(), conn, SignupEvent, user, config))

	assert.Equal(t, 1, callCount)
}

func TestSignupHookFromClaims(t *testing.T) {
	globalConfig, err := conf.LoadGlobal(apiTestConfig)
	require.NoError(t, err)

	conn, err := test.SetupDBConnection(globalConfig)
	require.NoError(t, err)

	user, err := models.NewUser("", "test@truth.com", "thisisapassword", "", nil)
	require.NoError(t, err)

	var callCount int
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		defer squash(r.Body.Close)
		raw, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		data := map[string]interface{}{}
		require.NoError(t, json.Unmarshal(raw, &data))

		assert.Len(t, data, 3)
		w.WriteHeader(http.StatusOK)
	}))
	defer svr.Close()

	config := &conf.GlobalConfiguration{
		Webhook: conf.WebhookConfig{
			Events: []string{"signup"},
		},
	}

	ctx := context.Background()
	ctx = withFunctionHooks(ctx, map[string][]string{
		"signup": {svr.URL},
	})

	require.NoError(t, triggerEventHooks(ctx, conn, SignupEvent, user, config))

	assert.Equal(t, 1, callCount)
}

func TestHookRetry(t *testing.T) {
	var callCount int
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		assert.EqualValues(t, 0, r.ContentLength)
		if callCount == 3 {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer svr.Close()

	config := &conf.WebhookConfig{
		URL:     svr.URL,
		Retries: 3,
	}
	w := Webhook{
		WebhookConfig: config,
	}
	b, err := w.trigger()
	defer func() {
		if b != nil {
			b.Close()
		}
	}()
	require.NoError(t, err)

	assert.Equal(t, 3, callCount)
}

func TestHookTimeout(t *testing.T) {
	realTimeout := defaultTimeout
	defer func() {
		defaultTimeout = realTimeout
	}()
	defaultTimeout = time.Millisecond * 10

	var mu sync.Mutex
	var callCount int
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		callCount++
		mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}))

	config := &conf.WebhookConfig{
		URL:     svr.URL,
		Retries: 3,
	}
	w := Webhook{
		WebhookConfig: config,
	}
	_, err := w.trigger()
	require.Error(t, err)
	herr, ok := err.(*HTTPError)
	require.True(t, ok)
	assert.Equal(t, http.StatusGatewayTimeout, herr.Code)

	svr.Close()
	assert.Equal(t, 3, callCount)
}

func squash(f func() error) { _ = f }
