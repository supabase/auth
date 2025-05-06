package api_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/e2e/e2eapi"
	"github.com/supabase/auth/internal/e2e/e2ehooks"
	"github.com/supabase/auth/internal/hooks/v1hooks"
	"github.com/supabase/auth/internal/models"
)

func TestE2EHooks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	globalCfg, err := conf.LoadGlobal("../../hack/test.env")
	if err != nil {
		t.Fatalf("exp nil err; got %v", err)
	}

	inst, err := e2ehooks.New(globalCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer inst.Close()

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
		}
	}
}
