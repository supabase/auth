package api

import (
	"context"
	"sync"

	"github.com/supabase/auth/internal/utilities"
)

var (
	cleanupWaitGroup sync.WaitGroup
)

// WaitForCleanup waits until all API servers are shut down cleanly or until
// the provided context signals done, whichever comes first.
func WaitForCleanup(ctx context.Context) {
	utilities.WaitForCleanup(ctx, &cleanupWaitGroup)
}
