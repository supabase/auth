package utilities

import (
	"context"
	"sync"
)

type contextKey string

func (c contextKey) String() string {
	return "gotrue api context key " + string(c)
}

const (
	requestIDKey = contextKey("request_id")
	hookDataKey  = contextKey("hook_data")
)

// MaxHookDataLength is the largest hook_data value accepted on any endpoint.
//
// It bounds a value that is written to the flow state for the duration of an
// external provider round trip, and that is copied into every hook payload for
// the request.
const MaxHookDataLength = 4096

// WithRequestID adds the provided request ID to the context.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

// GetRequestID reads the request ID from the context.
func GetRequestID(ctx context.Context) string {
	obj := ctx.Value(requestIDKey)
	if obj == nil {
		return ""
	}

	return obj.(string)
}

// WithHookData adds the caller-supplied hook data to the context.
//
// The value is opaque: it is carried from the request that begins a sign-up to
// the hooks invoked while serving it, and is never interpreted or persisted on
// the user record. It originates with the client, so a hook that acts on it
// must validate it.
func WithHookData(ctx context.Context, data string) context.Context {
	return context.WithValue(ctx, hookDataKey, data)
}

// GetHookData reads the caller-supplied hook data from the context, returning
// an empty string when the request carried none.
func GetHookData(ctx context.Context) string {
	obj := ctx.Value(hookDataKey)
	if obj == nil {
		return ""
	}

	return obj.(string)
}

// WaitForCleanup waits until all long-running goroutines shut
// down cleanly or until the provided context signals done.
func WaitForCleanup(ctx context.Context, wg *sync.WaitGroup) {
	cleanupDone := make(chan struct{})

	go func() {
		defer close(cleanupDone)

		wg.Wait()
	}()

	select {
	case <-ctx.Done():
		return

	case <-cleanupDone:
		return
	}
}
