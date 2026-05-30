package utilities

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestContextKeyString(t *testing.T) {
	require.Equal(t, "gotrue api context key request_id", contextKey("request_id").String())
	require.Equal(t, "gotrue api context key ", contextKey("").String())
}

func TestRequestIDRoundtrip(t *testing.T) {
	t.Run("set then read", func(t *testing.T) {
		ctx := WithRequestID(context.Background(), "abc-123")
		require.Equal(t, "abc-123", GetRequestID(ctx))
	})

	t.Run("missing key returns empty string", func(t *testing.T) {
		require.Equal(t, "", GetRequestID(context.Background()))
	})

	t.Run("set replaces previous value", func(t *testing.T) {
		ctx := WithRequestID(context.Background(), "first")
		ctx = WithRequestID(ctx, "second")
		require.Equal(t, "second", GetRequestID(ctx))
	})

	t.Run("derived context inherits value", func(t *testing.T) {
		ctx := WithRequestID(context.Background(), "parent-id")
		child, cancel := context.WithCancel(ctx)
		defer cancel()
		require.Equal(t, "parent-id", GetRequestID(child))
	})
}

func TestWaitForCleanup(t *testing.T) {
	t.Run("returns when wait group is done", func(t *testing.T) {
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			time.Sleep(10 * time.Millisecond)
			wg.Done()
		}()

		done := make(chan struct{})
		go func() {
			defer close(done)
			WaitForCleanup(context.Background(), &wg)
		}()

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("WaitForCleanup did not return after wg.Done()")
		}
	})

	t.Run("returns when context is cancelled before wait group is done", func(t *testing.T) {
		var wg sync.WaitGroup
		wg.Add(1)

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			WaitForCleanup(ctx, &wg)
		}()

		cancel()

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("WaitForCleanup did not return after context cancellation")
		}

		wg.Done()
	})
}
