package api_test

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api"
	"github.com/supabase/auth/internal/e2e"
	"github.com/supabase/auth/internal/e2e/e2eapi"
	"github.com/supabase/auth/internal/e2e/e2ehooks"
	"github.com/supabase/auth/internal/hooks/v0hooks"
	"github.com/supabase/auth/internal/hooks/v1hooks"
	"github.com/supabase/auth/internal/models"
)

func TestE2EHooks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	globalCfg := e2e.Must(e2e.Config())
	inst, err := e2ehooks.New(globalCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer inst.Close()

	apiSrv := inst.APIServer
	hookRec := inst.HookRecorder

	var currentUser *models.User

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
			err := e2eapi.Do(ctx, http.MethodPost, apiSrv.URL+"/signup", req, res)
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

			currentUser = signupUser
		}
	}

	// confirm & reload the current user
	{
		if err := currentUser.Confirm(inst.Conn); err != nil {
			t.Fatalf("exp nil err; got %v", err)
		}

		latest, err := models.FindUserByID(inst.Conn, currentUser.ID)
		if err != nil {
			t.Fatalf("exp nil err; got %v", err)
		}
		currentUser = latest
	}

	// Basic test for CustomizeAccessToken
	{
		hr := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				code := http.StatusInternalServerError
				http.Error(w, http.StatusText(code), code)
				return
			}
			w.Header().Add("content-type", "application/json")
			_, _ = w.Write(body)
		})
		hookRec.CustomizeAccessToken.SetHandler(hr)
		req := &api.PasswordGrantParams{
			Email:    string(currentUser.Email),
			Password: "password",
		}

		res := new(api.AccessTokenResponse)
		err := e2eapi.Do(ctx, http.MethodPost, apiSrv.URL+"/token?grant_type=password", req, res)
		if err != nil {
			t.Fatalf("exp nil err; got %v", err)
		}
		require.Equal(t, currentUser.Email.String(), res.User.Email.String())

		calls := hookRec.CustomizeAccessToken.GetCalls()
		if exp, got := 1, len(calls); exp != got {
			t.Fatalf("exp %v; got %v", exp, got)
		}
		call := calls[0]

		hookReq := &v0hooks.CustomAccessTokenInput{}
		if err := call.Unmarshal(hookReq); err != nil {
			t.Fatalf("exp nil err; got %v", err)
		}

		require.Equal(t, currentUser.ID, hookReq.UserID)
		require.Equal(t, currentUser.ID.String(), hookReq.Claims.Subject)
	}

	// Basic test for CustomizeAccessToken
	{
		hr := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Add("content-type", "application/json")
			_, _ = io.WriteString(w, `{"claims": {}}`)
		})

		hookRec.CustomizeAccessToken.ClearCalls()
		hookRec.CustomizeAccessToken.SetHandler(hr)
		req := &api.PasswordGrantParams{
			Email:    string(currentUser.Email),
			Password: "password",
		}

		res := new(api.AccessTokenResponse)
		err := e2eapi.Do(ctx, http.MethodPost, apiSrv.URL+"/token?grant_type=password", req, res)
		if err == nil {
			t.Fatal("exp non-nil err")
		}

		calls := hookRec.CustomizeAccessToken.GetCalls()
		if exp, got := 1, len(calls); exp != got {
			t.Fatalf("exp %v; got %v", exp, got)
		}
		call := calls[0]

		hookReq := &v0hooks.CustomAccessTokenInput{}
		if err := call.Unmarshal(hookReq); err != nil {
			t.Fatalf("exp nil err; got %v", err)
		}

		require.Equal(t, currentUser.ID, hookReq.UserID)
		require.Equal(t, currentUser.ID.String(), hookReq.Claims.Subject)
	}
}
