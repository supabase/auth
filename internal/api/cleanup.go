package api

import (
	"context"
	"sync"
)

var (
	cleanupWaitGroup sync.WaitGroup
)

// WaitForCleanup waits until all API servers are shut down cleanly or until
// the provided context signals done, whichever comes first.
func WaitForCleanup(ctx context.Context) {
	cleanupDone := make(chan struct{})

	go func() {
		defer close(cleanupDone)

		cleanupWaitGroup.Wait()
	}()

	select {
	case <-ctx.Done():
		return

	case <-cleanupDone:
		return
	}
}
