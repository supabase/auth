package hookafter

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/supabase/auth/internal/hooks/v0hooks"
)

func TestContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if exp, got := errCtx, Defer(ctx, `any`, func() error { return nil }); exp != got {
		t.Fatalf("exp err %v; got %v", exp, got)
	}
	if exp, got := errCtx, Fire(ctx); exp != got {
		t.Fatalf("exp err %v; got %v", exp, got)
	}

	ctx = With(ctx)
	st := from(ctx)
	if st == nil {
		t.Fatal("exp non-nil *state")
	}

	if exp, got := st, from(ctx); exp != got {
		t.Fatalf("exp same state %v; got %v", exp, got)
	}

	if err := Defer(ctx, `any`, func() error { return nil }); err != nil {
		t.Fatalf("exp nil err; got %v", err)
	}
	if err := Fire(ctx); err != nil {
		t.Fatalf("exp nil err; got %v", err)
	}
}

func TestState(t *testing.T) {
	var calls []v0hooks.Name
	triggerFn := func(name v0hooks.Name) (v0hooks.Name, func() error) {
		return name, func() error {
			calls = append(calls, name)
			return nil
		}
	}

	hookNames := []v0hooks.Name{
		`after-user-created`,
		`after-identity-created`,
		`after-identity-linking`,
	}

	st := newState()
	for _, hookName := range hookNames {
		st.add(triggerFn(hookName))
	}

	if exp, got := 0, len(calls); exp != got {
		t.Fatalf("exp %v; got %v", exp, got)
	}

	if err := st.fire(); err != nil {
		t.Fatalf("exp nil err; got %v", err)
	}
	if exp, got := len(hookNames), len(calls); exp != got {
		t.Fatalf("exp %v; got %v", exp, got)
	}

	hookNamesRev := slices.Clone(hookNames)
	slices.Reverse(hookNamesRev)

	for i, hookName := range hookNamesRev {
		if exp, got := hookName, calls[i]; exp != got {
			t.Fatalf("exp %v; got %v", exp, got)
		}
	}

	// double fire fails
	if err := st.fire(); err == nil {
		t.Fatal("exp non-nil err")
	}
}

func TestStateErrors(t *testing.T) {
	var calls []v0hooks.Name
	sentinel := errors.New("sentinel")
	triggerFn := func(name v0hooks.Name) (v0hooks.Name, func() error) {
		return name, func() error {
			calls = append(calls, name)
			return sentinel
		}
	}

	hookNames := []v0hooks.Name{
		`after-user-created`,
		`after-identity-created`,
		`after-identity-linking`,
	}

	st := newState()
	for _, hookName := range hookNames {
		st.add(triggerFn(hookName))
	}
	if exp, got := 0, len(calls); exp != got {
		t.Fatalf("exp %v; got %v", exp, got)
	}

	fireErr := st.fire()
	if fireErr == nil {
		t.Fatal("exp non-nil err")
	}
	if exp, got := len(hookNames), len(calls); exp != got {
		t.Fatalf("exp %v; got %v", exp, got)
	}

	hookNamesRev := slices.Clone(hookNames)
	slices.Reverse(hookNamesRev)

	var b strings.Builder
	for i, hookName := range hookNamesRev {
		if exp, got := hookName, calls[i]; exp != got {
			t.Fatalf("exp %v; got %v", exp, got)
		}

		b.WriteString(string(hookName) + ": sentinel\n")
	}

	expErrStr := strings.TrimRight(b.String(), "\n")
	if exp, got := expErrStr, fireErr.Error(); exp != got {
		t.Fatalf("exp %v; got %v", exp, got)
	}

	// double fire fails
	if err := st.fire(); err == nil {
		t.Fatal("exp non-nil err")
	}
	if err := st.add(triggerFn(`any`)); err == nil {
		t.Fatal("exp non-nil err")
	}
}
