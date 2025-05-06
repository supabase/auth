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

/*

func TestUserHooks(t *testing.T) {
	t.SkipNow()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	globalCfg, err := conf.LoadGlobal("../../../hack/test.env")
	if err != nil {
		t.Fatalf("exp nil err; got %v", err)
	}

	inst, err := New(globalCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer inst.Close()

	apiCli := inst.APIClient
	apiSrv := inst.APIServer
	hookRec := inst.HookRecorder

	// Basic tests for Before/After User Created hooks
	{

		// Signup a user
		var signupUser *models.User
		email := "e2etesthooks_" + uuid.Must(uuid.NewV4()).String() + "@localhost"
		{
			req := &api.SignupParams{
				Email:    email,
				Password: "password",
			}
			res := new(models.User)
			err := apiCli.Do(ctx, http.MethodPost, apiSrv.URL+"/signup", req, res)
			if err != nil {
				t.Fatalf("exp nil err; got %v", err)
			}
			signupUser = res

			require.Equal(t, email, signupUser.Email.String())
		}

		{
			calls := hookRec.BeforeUserCreated.GetCalls()
			if exp, got := 1, len(calls); exp != got {
				t.Fatalf("exp %v; got %v", exp, got)
			}
			call := calls[0]

			hookReq := &v1hooks.BeforeUserCreatedRequest{}
			if err := call.Unmarshal(hookReq); err != nil {
				t.Fatalf("exp nil err; got %v", err)
			}

			u := hookReq.User
			require.Equal(t, signupUser.ID, u.ID)
			require.Equal(t, signupUser.Aud, u.Aud)
			require.Equal(t, signupUser.Email, u.Email)
			require.Equal(t, signupUser.AppMetaData, u.AppMetaData)

			require.True(t, u.CreatedAt.IsZero())
			require.True(t, u.UpdatedAt.IsZero())
		}

		{
			calls := hookRec.AfterUserCreated.GetCalls()
			if exp, got := 1, len(calls); exp != got {
				t.Fatalf("exp %v; got %v", exp, got)
			}
			call := calls[0]

			hookReq := &v1hooks.AfterUserCreatedRequest{}
			if err := call.Unmarshal(hookReq); err != nil {
				t.Fatalf("exp nil err; got %v", err)
			}

			u := hookReq.User
			require.Equal(t, signupUser.ID, u.ID)
			require.Equal(t, signupUser.Aud, u.Aud)
			require.Equal(t, signupUser.Role, u.Role)
			require.Equal(t, signupUser.Email, u.Email)
			require.Equal(t, signupUser.AppMetaData, u.AppMetaData)

			require.Equal(t, signupUser.CreatedAt, u.CreatedAt)
			require.True(t, signupUser.CreatedAt.Before(u.UpdatedAt))
			require.True(t, signupUser.UpdatedAt.After(u.UpdatedAt))
		}
	}
}

*/
