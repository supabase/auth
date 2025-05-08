// Package hookafter contains utilities for contextually queueing and firing
// hooks in LIFO order.
package hookafter

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/hooks/v0hooks"
)

type trigger struct {
	name v0hooks.Name
	fn   func() error
}

type state struct {
	mu    sync.Mutex
	done  bool
	queue []*trigger
}

func newState() *state {
	return &state{}
}

func (o *state) fire() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.done {
		err := errors.New("invalid call to Fire")
		return apierrors.NewInternalServerError(
			"error triggering hooks").WithInternalError(err)
	}
	o.done = true

	var errs []error
	for i := len(o.queue) - 1; i >= 0; i-- {
		tr := o.queue[i]
		err := tr.fn()
		if err != nil {
			errs = append(errs, fmt.Errorf("%v: %w", tr.name, err))
		}
	}
	return errors.Join(errs...)
}

func (o *state) add(name v0hooks.Name, fn func() error) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.done {
		err := errors.New("call to Defer after all triggers have fired")
		return apierrors.NewInternalServerError(
			"error triggering hooks").WithInternalError(err)
	}

	tr := &trigger{
		fn:   fn,
		name: name,
	}
	o.queue = append(o.queue, tr)
	return nil
}

var (
	ctxKey         = new(int)
	ctxErrInternal = errors.New("context is missing *hookafter.state")
	ctxErr         = apierrors.NewInternalServerError(
		"context is missing unable to trigger hooks").
		WithInternalError(ctxErrInternal)
)

// Fire will call each trigger previously queued with Defer and return a nil
// error. If err is non-nil it will be 1 or more errors that occurred during
// firing joined by errors.Join().
func Fire(ctx context.Context) error {
	st := from(ctx)
	if st == nil {
		return ctxErr
	}
	return st.fire()
}

// Defer will queue a trigger in LIFO order much like the defer built-in. It
// will return an error if Fire has already been called.
func Defer(
	ctx context.Context,
	name v0hooks.Name,
	fn func() error,
) error {
	st := from(ctx)
	if st == nil {
		return ctxErr
	}
	return st.add(name, fn)
}

// With sets up the given context for adding triggers.
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
