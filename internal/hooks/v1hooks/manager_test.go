package v1hooks

import (
	"context"
	"errors"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/hooks/v0hooks"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

func TestNew(t *testing.T) {
	const sentinelStr = "sentinel"
	r := httptest.NewRequest("GET", "http://localhost/test", nil)
	r.Header.Set("x-forwarded-for", "1.2.3.4")
	now := time.Now()

	checkHeader := func(hdr *Header, name v0hooks.Name) {
		if exp, got := false, hdr.UUID.IsNil(); exp != got {
			t.Fatalf("exp %v; got %v", exp, got)
		}
		if exp, got := false, now.After(hdr.Time); exp != got {
			t.Fatalf("exp %v; got %v", exp, got)
		}
		if exp, got := name, hdr.Name; exp != got {
			t.Fatalf("exp %v; got %v", exp, got)
		}
		if exp, got := "1.2.3.4", hdr.IPAddress; exp != got {
			t.Fatalf("exp %v; got %v", exp, got)
		}
	}

	{
		hdr := NewHeader(r, v0hooks.SendEmail)
		if hdr == nil {
			t.Fatal("exp non-nil *Header")
		}
		checkHeader(hdr, v0hooks.SendEmail)
	}

	{
		user := &models.User{
			Aud: sentinelStr,
		}
		req := NewBeforeUserCreatedRequest(r, user)
		if req == nil {
			t.Fatal("exp non-nil *Header")
		}
		checkHeader(req.Header, BeforeUserCreated)

		if exp, got := user, req.User; exp != got {
			t.Fatalf("exp %v; got %v", exp, got)
		}
		if exp, got := sentinelStr, req.User.Aud; exp != got {
			t.Fatalf("exp %v; got %v", exp, got)
		}
	}

	{
		user := &models.User{
			Aud: sentinelStr,
		}
		req := NewAfterUserCreatedRequest(r, user)
		if req == nil {
			t.Fatal("exp non-nil *Header")
		}
		checkHeader(req.Header, AfterUserCreated)

		if exp, got := user, req.User; exp != got {
			t.Fatalf("exp %v; got %v", exp, got)
		}
		if exp, got := sentinelStr, req.User.Aud; exp != got {
			t.Fatalf("exp %v; got %v", exp, got)
		}
	}
}

func TestConfig(t *testing.T) {
	cfg := helpConfig(false)
	mockSvc := new(mockService)
	mr := New(cfg, mockSvc)

	tests := []struct {
		cfg  *conf.HookConfiguration
		name v0hooks.Name
		exp  *conf.ExtensibilityPointConfiguration
		ok   bool
	}{
		{},
		{cfg: cfg, ok: true,
			name: BeforeUserCreated, exp: &cfg.BeforeUserCreated},
		{cfg: cfg, ok: true,
			name: AfterUserCreated, exp: &cfg.AfterUserCreated},
	}
	for idx, test := range tests {
		t.Logf("test #%v - exp ok %v with cfg %v from name %v",
			idx, test.ok, test.exp, test.name)

		require.Equal(t, false, mr.Enabled(test.name))

		got, ok := configByName(test.cfg, test.name)
		require.Equal(t, test.ok, ok)
		require.Equal(t, test.exp, got)

		if got == nil {
			continue
		}

		got.Enabled = true
		require.Equal(t, true, mr.Enabled(test.name))
	}
}

func TestHooks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	t.Run("BeforeUserCreated", func(t *testing.T) {
		httpReq := httptest.NewRequest("GET", "http://localhost/test", nil)
		user := &models.User{}
		req := NewBeforeUserCreatedRequest(httpReq, user)
		res := new(BeforeUserCreatedResponse)

		t.Run("BeforeUserCreatedSuccess", func(t *testing.T) {
			cfg := helpConfig(true)
			dr := newMockService(nil)
			mr := New(cfg, dr)

			err := mr.BeforeUserCreated(ctx, nil, req, res)
			if err != nil {
				t.Fatalf("exp nil err; got %v", err)
			}
			if exp, got := 1, len(dr.calls); exp != got {
				t.Fatalf("exp %v; got %v", exp, got)
			}

			call := dr.calls[0]
			if exp, got := req, call.input; exp != got {
				t.Fatalf("exp %v; got %v", exp, got)
			}
			if exp, got := res, call.output; exp != got {
				t.Fatalf("exp %v; got %v", exp, got)
			}
		})

		t.Run("BeforeUserCreatedError", func(t *testing.T) {
			cfg := helpConfig(true)
			sentinel := errors.New("sentinel")
			dr := newMockService(sentinel)
			mr := New(cfg, dr)

			err := mr.BeforeUserCreated(ctx, nil, req, res)
			if err != sentinel {
				t.Fatalf("exp err %v; got %v", sentinel, err)
			}
			if exp, got := 1, len(dr.calls); exp != got {
				t.Fatalf("exp %v; got %v", exp, got)
			}

			call := dr.calls[0]
			if exp, got := req, call.input; exp != got {
				t.Fatalf("exp %v; got %v", exp, got)
			}
			if exp, got := res, call.output; exp != got {
				t.Fatalf("exp %v; got %v", exp, got)
			}
		})
	})

	t.Run("AfterUserCreated", func(t *testing.T) {
		httpReq := httptest.NewRequest("GET", "http://localhost/test", nil)
		user := &models.User{}
		req := NewAfterUserCreatedRequest(httpReq, user)
		res := new(AfterUserCreatedResponse)

		t.Run("AfterUserCreatedSuccess", func(t *testing.T) {
			cfg := helpConfig(true)
			dr := newMockService(nil)
			mr := New(cfg, dr)

			err := mr.AfterUserCreated(ctx, nil, req, res)
			if err != nil {
				t.Fatalf("exp nil err; got %v", err)
			}
			if exp, got := 1, len(dr.calls); exp != got {
				t.Fatalf("exp %v; got %v", exp, got)
			}

			call := dr.calls[0]
			if exp, got := req, call.input; exp != got {
				t.Fatalf("exp %v; got %v", exp, got)
			}
			if exp, got := res, call.output; exp != got {
				t.Fatalf("exp %v; got %v", exp, got)
			}
		})

		t.Run("AfterUserCreatedError", func(t *testing.T) {
			cfg := helpConfig(true)
			sentinel := errors.New("sentinel")
			dr := newMockService(sentinel)
			mr := New(cfg, dr)

			err := mr.AfterUserCreated(ctx, nil, req, res)
			if err != sentinel {
				t.Fatalf("exp err %v; got %v", sentinel, err)
			}
			if exp, got := 1, len(dr.calls); exp != got {
				t.Fatalf("exp %v; got %v", exp, got)
			}

			call := dr.calls[0]
			if exp, got := req, call.input; exp != got {
				t.Fatalf("exp %v; got %v", exp, got)
			}
			if exp, got := res, call.output; exp != got {
				t.Fatalf("exp %v; got %v", exp, got)
			}
		})
	})
}

func helpConfig(enabled bool) *conf.HookConfiguration {
	cfg := &conf.HookConfiguration{
		BeforeUserCreated: conf.ExtensibilityPointConfiguration{
			URI:     "http:localhost/" + string(BeforeUserCreated),
			Enabled: enabled,
		},
		AfterUserCreated: conf.ExtensibilityPointConfiguration{
			URI:     "http:localhost/" + string(AfterUserCreated),
			Enabled: enabled,
		},
	}
	return cfg
}

type mockCall struct {
	conn          *storage.Connection
	hookConfig    *conf.ExtensibilityPointConfiguration
	input, output any
}

type mockService struct {
	mu    sync.Mutex
	err   error
	calls []*mockCall
}

func newMockService(err error) *mockService { return &mockService{err: err} }

func (o *mockService) Dispatch(
	ctx context.Context,
	hookConfig *conf.ExtensibilityPointConfiguration,
	conn *storage.Connection,
	input, output any,
) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.calls = append(o.calls, &mockCall{
		conn:       conn,
		hookConfig: hookConfig,
		input:      input,
		output:     output,
	})
	return o.err
}
