// Package taskafter contains utilities for contextually queueing and firing
// tasks in FIFO order.
package taskafter

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/observability"
)

func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(With(r.Context()))
		defer func() {
			if err := Fire(r.Context()); err != nil {
				log := observability.GetLogEntry(r).Entry
				log.WithError(err).Warn("error running 1 or more tasks")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type task struct {
	name string
	fn   func() error
}

type state struct {
	mu    sync.Mutex
	done  bool
	queue []*task
	seen  map[string]bool
}

func newState() *state {
	return &state{seen: make(map[string]bool)}
}

func (o *state) fire() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.done {
		err := fmt.Errorf("%w: duplicate call to Fire", errPkg)
		return apierrors.NewInternalServerError(
			"error tasking hooks").WithInternalError(err)
	}
	o.done = true

	var errs []error
	for _, tr := range o.queue {
		err := tr.fn()
		if err != nil {
			errs = append(errs, fmt.Errorf("%v: %w", tr.name, err))
		}
	}
	return errors.Join(errs...)
}

func (o *state) add(name string, fn func() error) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.done {
		err := fmt.Errorf("%w: unable to add tasks after a call to Fire", errPkg)
		return apierrors.NewInternalServerError(
			"failed to add task").WithInternalError(err)
	}
	if name != "" {
		if o.seen[name] {
			return nil
		}
		o.seen[name] = true
	}

	tr := &task{
		fn:   fn,
		name: name,
	}
	o.queue = append(o.queue, tr)
	return nil
}

var (
	ctxKey         = new(int)
	errPkg         = errors.New("taskafter")
	errCtxInternal = fmt.Errorf(
		"%w: context is missing *taskafter.state", errPkg)
	errCtx = apierrors.NewInternalServerError(
		"unable to queue or run tasks").
		WithInternalError(errCtxInternal)
)

// Fire will call each queued task previously queued with Defer and return a nil
// error. If err is non-nil it will be 1 or more errors that occurred during
// firing joined by errors.Join().
func Fire(ctx context.Context) error {
	st := from(ctx)
	if st == nil {
		return errCtx
	}
	return st.fire()
}

// Once will queue the first task given by name to run at the end of the request
// in FIFO order or return an error if Fire has already been called.
func Once(ctx context.Context, name string, taskFn func() error) error {
	return add(ctx, name, taskFn)
}

// Queue will queue a task to run at the end of the request in FIFO order or
// return an error if Fire has already been called.
func Queue(ctx context.Context, taskFn func() error) error {
	return add(ctx, "", taskFn)
}

func add(ctx context.Context, name string, taskFn func() error) error {
	st := from(ctx)
	if st == nil {
		return errCtx
	}
	return st.add(name, taskFn)
}

// With sets up the given context for adding tasks.
func With(ctx context.Context) context.Context {
	st := from(ctx)
	if st == nil {
		st = newState()
	}
	return context.WithValue(ctx, ctxKey, st)
}

func from(ctx context.Context) *state {
	if st, ok := ctx.Value(ctxKey).(*state); ok && st != nil {
		return st
	}
	return nil
}
