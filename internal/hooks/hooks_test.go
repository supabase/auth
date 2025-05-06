package hooks_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/e2e"
	"github.com/supabase/auth/internal/hooks"
	"github.com/supabase/auth/internal/hooks/v0hooks"
	"github.com/supabase/auth/internal/hooks/v1hooks"
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

func (*mockService) RunHTTPHook(
	r *http.Request,
	hookConfig conf.ExtensibilityPointConfiguration,
	input any,
) ([]byte, error) {
	return nil, nil
}

func (*mockService) BeforeUserCreated(
	ctx context.Context,
	tx *storage.Connection,
	req *v1hooks.BeforeUserCreatedRequest,
	res *v1hooks.BeforeUserCreatedResponse,
) error {
	return nil
}

func (*mockService) AfterUserCreated(
	ctx context.Context,
	tx *storage.Connection,
	req *v1hooks.AfterUserCreatedRequest,
	res *v1hooks.AfterUserCreatedResponse,
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
	mgr := hooks.NewFromServices(svc, svc)

	{
		ok := mgr.Enabled(v1hooks.AfterUserCreated)
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
		cfg := conf.ExtensibilityPointConfiguration{}
		data, err := mgr.RunHTTPHook(nil, cfg, nil)
		if err != nil {
			t.Fatalf("exp nil err; got %v", err)
		}
		if len(data) > 0 {
			t.Fatal("exp mock svc to return no data")
		}
	}

	{
		req := new(v1hooks.BeforeUserCreatedRequest)
		res := new(v1hooks.BeforeUserCreatedResponse)
		err := mgr.BeforeUserCreated(ctx, nil, req, res)
		if err != nil {
			t.Fatalf("exp nil err; got %v", err)
		}
	}

	{
		req := new(v1hooks.BeforeUserCreatedRequest)
		res := new(v1hooks.BeforeUserCreatedResponse)
		err := mgr.BeforeUserCreated(ctx, nil, req, res)
		if err != nil {
			t.Fatalf("exp nil err; got %v", err)
		}
	}

	{
		req := new(v1hooks.AfterUserCreatedRequest)
		res := new(v1hooks.AfterUserCreatedResponse)
		err := mgr.AfterUserCreated(ctx, nil, req, res)
		if err != nil {
			t.Fatalf("exp nil err; got %v", err)
		}
	}
}
