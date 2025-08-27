package apitask

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type taskFunc struct {
	typ string
	fn  func(context.Context) error
}

func (o *taskFunc) Type() string { return o.typ }

func (o *taskFunc) Run(ctx context.Context) error { return o.fn(ctx) }

func taskFn(typ string, fn func(context.Context) error) Task {
	return &taskFunc{typ: typ, fn: fn}
}

func TestRequestWorker(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()

	t.Run("RunTasks", func(t *testing.T) {
		{
			rw, ok := from(ctx)
			require.False(t, ok, "request worker must not found in context")
			require.Nil(t, rw, "request worker must be nil")
		}

		withCtx := With(ctx)
		{
			rw, ok := from(withCtx)
			require.True(t, ok, "request worker not found in context")
			require.NotNil(t, rw, "request worker was nil")

			withCtxDupe := With(withCtx)
			sameRw, ok := from(withCtxDupe)
			require.True(t, ok, "request worker not found in context")
			require.True(t, rw == sameRw, "request worker should be created only once")
		}
	})

	t.Run("RunTasks", func(t *testing.T) {
		withCtx := With(ctx)

		calls := new(atomic.Int64)
		expCalls := 0
		for range 16 {
			expCalls++
			task := taskFn("test.run", func(ctx context.Context) error {
				calls.Add(1)
				return nil
			})
			err := Run(withCtx, task)
			require.NoError(t, err)
		}

		{
			Wait(withCtx)

			gotCalls := int(calls.Load())
			require.Equal(t, expCalls, gotCalls)
		}
	})
}
