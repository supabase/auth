package observability

import (
	"context"
	"testing"
	"time"
)

func TestWaitForCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		WaitForCleanup(ctx)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("WaitForCleanup did not return after context cancellation")
	}
}
