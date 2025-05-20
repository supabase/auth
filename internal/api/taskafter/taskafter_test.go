package taskafter

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err := Once(ctx, `any`, func() error { return nil })
	require.Equal(t, errCtx, err)
	require.Equal(t, errCtx, Fire(ctx))

	ctx = With(ctx)
	st := from(ctx)
	require.NotNil(t, st)
	require.Equal(t, st, from(ctx))

	err = Once(ctx, `any`, func() error { return nil })
	require.NoError(t, err)

	err = Queue(ctx, func() error { return nil })
	require.NoError(t, err)

	err = Fire(ctx)
	require.NoError(t, err)
}

func TestState(t *testing.T) {
	var calls []string
	triggerFn := func(name string) (string, func() error) {
		return name, func() error {
			calls = append(calls, name)
			return nil
		}
	}

	taskNames := []string{
		`after-user-created`,
		`after-identity-created`,
		`after-identity-linking`,
	}

	st := newState()
	for _, taskName := range taskNames {
		err := st.add(triggerFn(taskName))
		require.NoError(t, err)
	}

	require.Equal(t, 0, len(calls))

	err := st.fire()
	require.NoError(t, err)
	require.Equal(t, len(taskNames), len(calls))

	for i, taskName := range taskNames {
		require.Equal(t, taskName, calls[i])
	}

	// double fire fails
	if err := st.fire(); err == nil {
		t.Fatal("exp non-nil err")
	}
}

func TestStateErrors(t *testing.T) {
	var calls []string
	sentinel := errors.New("sentinel")
	triggerFn := func(name string) (string, func() error) {
		return name, func() error {
			calls = append(calls, name)
			return sentinel
		}
	}

	taskNames := []string{
		`after-user-created`,
		`after-identity-created`,
		`after-identity-linking`,
	}

	st := newState()
	for _, taskName := range taskNames {
		if err := st.add(triggerFn(taskName)); err != nil {
			t.Fatalf("exp nil error; got %v", err)
		}

		// double trigger should just be ignored, less burden on callers
		require.NoError(t, st.add(triggerFn(taskName)))
	}
	require.Equal(t, 0, len(calls))

	fireErr := st.fire()
	require.Error(t, fireErr)
	require.Equal(t, len(taskNames), len(calls))

	var b strings.Builder
	for i, taskName := range taskNames {
		require.Equal(t, taskName, calls[i])
		b.WriteString(string(taskName) + ": sentinel\n")
	}

	expErrStr := strings.TrimRight(b.String(), "\n")
	require.Equal(t, expErrStr, fireErr.Error())

	// double fire fails
	require.Error(t, st.fire())
	require.Error(t, st.add(triggerFn(`any`)))
}
