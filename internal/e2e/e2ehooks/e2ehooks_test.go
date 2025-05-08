package e2ehooks

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/hooks/v0hooks"
	"github.com/supabase/auth/internal/hooks/v1hooks"
)

func TestInstance(t *testing.T) {
	{
		globalCfg, err := conf.LoadGlobal("../../../hack/test.env")
		if err != nil {
			t.Fatalf("exp nil err; got %v", err)
		}
		globalCfg.DB.Driver = ""
		globalCfg.DB.URL = "invalid"

		inst, err := New(globalCfg)
		if err == nil {
			t.Fatal("exp non-nil err")
		}
		if inst != nil {
			t.Fatal("exp nil *Instance")
		}
	}

	{
		globalCfg, err := conf.LoadGlobal("../../../hack/test.env")
		if err != nil {
			t.Fatalf("exp nil err; got %v", err)
		}

		inst, err := New(globalCfg)
		if err != nil {
			t.Fatalf("exp nil err; got %v", err)
		}
		if inst == nil {
			t.Fatal("exp non-nil *Instance")
		}
		if err := inst.Close(); err != nil {
			t.Fatalf("exp nil err from Close; got %v", err)
		}
	}
}

func TestHook(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	hook := NewHook(v1hooks.AfterUserCreated)

	{
		calls := hook.GetCalls()
		if exp, got := 0, len(calls); exp != got {
			t.Fatalf("exp %v; got %v", exp, got)
		}

		u := "http://localhost"
		rdr := strings.NewReader("12345")
		req := httptest.NewRequestWithContext(ctx, "POST", u, rdr)
		res := httptest.NewRecorder()

		hook.ServeHTTP(res, req)

		calls = hook.GetCalls()
		if exp, got := 1, len(calls); exp != got {
			t.Fatalf("exp %v; got %v", exp, got)
		}
		call := calls[0]

		var got int
		if err := call.Unmarshal(&got); err != nil {
			t.Fatalf("exp nil err; got %v", err)
		}
		if exp := 12345; exp != got {
			t.Fatalf("exp %v; got %v", exp, got)
		}
	}

	{
		u := "http://localhost/hooks/before-user-created"
		sentinel := errors.New("sentinel")
		rdr := iotest.ErrReader(sentinel)
		req := httptest.NewRequestWithContext(ctx, "POST", u, rdr)
		res := httptest.NewRecorder()

		hook.ServeHTTP(res, req)
	}
}

func TestHookRecorder(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	hookRec := NewHookRecorder()
	tests := []struct {
		name v0hooks.Name
		hook *Hook
	}{
		{
			name: v1hooks.BeforeUserCreated,
			hook: hookRec.BeforeUserCreated,
		},
		{
			name: v1hooks.AfterUserCreated,
			hook: hookRec.AfterUserCreated,
		},
		{
			name: v0hooks.CustomizeAccessToken,
			hook: hookRec.CustomizeAccessToken,
		},
		{
			name: v0hooks.MFAVerification,
			hook: hookRec.MFAVerification,
		},
		{
			name: v0hooks.PasswordVerification,
			hook: hookRec.PasswordVerification,
		},
		{
			name: v0hooks.SendEmail,
			hook: hookRec.SendEmail,
		},
		{
			name: v0hooks.SendSMS,
			hook: hookRec.SendSMS,
		},
	}

	for _, test := range tests {

		{
			calls := test.hook.GetCalls()
			if exp, got := 0, len(calls); exp != got {
				t.Fatalf("exp %v; got %v", exp, got)
			}
		}

		u := "http://localhost/hooks/" + string(test.name)
		rdr := strings.NewReader("12345")
		req := httptest.NewRequestWithContext(ctx, "POST", u, rdr)
		res := httptest.NewRecorder()
		hookRec.ServeHTTP(res, req)

		{
			calls := test.hook.GetCalls()
			if exp, got := 1, len(calls); exp != got {
				t.Fatalf("exp %v; got %v", exp, got)
			}
			call := calls[0]

			test.hook.ClearCalls()
			if exp, got := 0, len(test.hook.GetCalls()); exp != got {
				t.Fatalf("exp %v; got %v", exp, got)
			}

			var got int
			if err := call.Unmarshal(&got); err != nil {
				t.Fatalf("exp nil err; got %v", err)
			}
			if exp := 12345; exp != got {
				t.Fatalf("exp %v; got %v", exp, got)
			}
		}
	}

	// not found
	{
		u := "http://localhost/hooks/__invalid-hook-name__"
		rdr := strings.NewReader("12345")
		req := httptest.NewRequestWithContext(ctx, "POST", u, rdr)
		res := httptest.NewRecorder()
		hookRec.ServeHTTP(res, req)

		if exp, got := 404, res.Result().StatusCode; exp != got {
			t.Fatalf("exp %v; got %v", exp, got)
		}
	}
}
