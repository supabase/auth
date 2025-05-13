package hooks_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/supabase/auth/internal/e2e"
	"github.com/supabase/auth/internal/hooks"
	"github.com/supabase/auth/internal/hooks/v0hooks"
	"github.com/supabase/auth/internal/storage"
)

type mockService struct{}

func (*mockService) Enabled(v0hooks.Name) bool { return true }

func (*mockService) InvokeHook(
	conn *storage.Connection,
	r *http.Request,
	input, output any,
) error {
	return nil
}

func (*mockService) BeforeUserCreated(
	ctx context.Context,
	tx *storage.Connection,
	req *v0hooks.BeforeUserCreatedInput,
	res *v0hooks.BeforeUserCreatedOutput,
) error {
	return nil
}

func (*mockService) AfterUserCreated(
	ctx context.Context,
	tx *storage.Connection,
	req *v0hooks.AfterUserCreatedInput,
	res *v0hooks.AfterUserCreatedOutput,
) error {
	return nil
}

func TestNew(t *testing.T) {
	globalCfg := e2e.Must(e2e.Config())
	conn := e2e.Must(e2e.Conn(globalCfg))
	mgr := hooks.New(globalCfg, conn)
	if mgr == nil {
		t.Fatal("exp non-nil *Manager")
	}
}

func TestManager(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	svc := &mockService{}
	mgr := hooks.NewFromService(svc)

	{
		ok := mgr.Enabled(v0hooks.AfterUserCreated)
		if exp, got := true, ok; exp != got {
			t.Fatalf("exp %v; got %v", exp, got)
		}
	}

	{
		err := mgr.InvokeHook(nil, nil, nil, nil)
		if err != nil {
			t.Fatalf("exp nil err; got %v", err)
		}
	}

	{
		req := new(v0hooks.BeforeUserCreatedInput)
		res := new(v0hooks.BeforeUserCreatedOutput)
		err := mgr.BeforeUserCreated(ctx, nil, req, res)
		if err != nil {
			t.Fatalf("exp nil err; got %v", err)
		}
	}

	{
		req := new(v0hooks.AfterUserCreatedInput)
		res := new(v0hooks.AfterUserCreatedOutput)
		err := mgr.AfterUserCreated(ctx, nil, req, res)
		if err != nil {
			t.Fatalf("exp nil err; got %v", err)
		}
	}
}
