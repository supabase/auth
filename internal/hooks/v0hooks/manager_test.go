package v0hooks

import (
	"context"
	"errors"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/e2e"
	"github.com/supabase/auth/internal/hooks/hookhttp"
	"github.com/supabase/auth/internal/hooks/hookpgfunc"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

type M = map[string]any

var testUUID = uuid.Must(uuid.FromString(
	"00000000-0000-0000-0000-000000000000"))

func TestHooks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	globalCfg := e2e.Must(e2e.Config())
	db := e2e.Must(e2e.Conn(globalCfg))
	httpDr := hookhttp.New(hookhttp.WithTimeout(time.Second / 10))
	pgfuncDr := hookpgfunc.New(db, hookpgfunc.WithTimeout(time.Second/10))
	mr := New(globalCfg, httpDr, pgfuncDr)
	now := time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC)

	// cover RunHTTPHook
	{
		globalCfg.Hook.SendSMS =
			conf.ExtensibilityPointConfiguration{
				URI: `http://0.0.0.0:12345`,
			}

		req := &SendSMSInput{}
		htr := httptest.NewRequestWithContext(ctx, "POST", "/api", nil)
		_, err := mr.RunHTTPHook(htr, globalCfg.Hook.SendSMS, req)
		if err == nil {
			t.Fatal("exp non-nil err")
		}
	}

	type testCase struct {
		desc   string
		setup  func()
		sql    string
		req    any
		res    any
		exp    any
		errStr string
	}

	cases := []testCase{

		{
			desc: "fail - send_sms http",
			setup: func() {
				globalCfg.Hook.SendSMS =
					conf.ExtensibilityPointConfiguration{
						URI: `http://0.0.0.0:12345`,
					}
			},
			req:    &SendSMSInput{},
			res:    &SendSMSOutput{},
			exp:    &SendSMSOutput{},
			errStr: "422: Failed to reach hook within maximum time of 0.100000 seconds",
		},

		{
			desc: "pass - send_sms",
			setup: func() {
				globalCfg.Hook.SendSMS =
					conf.ExtensibilityPointConfiguration{
						URI: `pg-functions://postgres/auth/` +
							`v0hooks_test_send_sms`,
						HookName: `"auth"."v0hooks_test_send_sms"`,
					}
			},
			req: &SendSMSInput{},
			res: &SendSMSOutput{},
			exp: &SendSMSOutput{},
			sql: `
				create or replace function
					v0hooks_test_send_sms(input jsonb)
				returns json as $$
				begin
					return '{}'::jsonb;
				end; $$ language plpgsql;`,
		},

		{
			desc: "pass - send_email",
			setup: func() {
				globalCfg.Hook.SendEmail =
					conf.ExtensibilityPointConfiguration{
						URI: `pg-functions://postgres/auth/` +
							`v0hooks_test_send_email`,
						HookName: `"auth"."v0hooks_test_send_email"`,
					}
			},
			req: &SendEmailInput{},
			res: &SendEmailOutput{},
			exp: &SendEmailOutput{},
			sql: `
				create or replace function
					v0hooks_test_send_email(input jsonb)
				returns json as $$
				begin
					return '{}'::jsonb;
				end; $$ language plpgsql;`,
		},

		{
			desc: "pass - mfa_verification_attempt",
			setup: func() {
				globalCfg.Hook.MFAVerificationAttempt =
					conf.ExtensibilityPointConfiguration{
						URI: `pg-functions://postgres/auth/` +
							`v0hooks_test_mfa_verification_attempt`,
						HookName: `"auth"."v0hooks_test_mfa_verification_attempt"`,
					}
			},
			req: &MFAVerificationAttemptInput{
				FactorID: testUUID,
				UserID:   testUUID,
				Valid:    true,
			},
			res: &MFAVerificationAttemptOutput{},
			exp: &MFAVerificationAttemptOutput{
				Decision: "reject",
				Message:  "Too many MFA attempts.",
			},
			sql: `
				create or replace function
					v0hooks_test_mfa_verification_attempt(input jsonb)
				returns json as $$
				begin
					return '{"decision":"reject","message":"Too many MFA attempts."}'::jsonb;
				end; $$ language plpgsql;`,
		},

		{
			desc: "pass - password_verification_attempt",
			setup: func() {
				globalCfg.Hook.PasswordVerificationAttempt =
					conf.ExtensibilityPointConfiguration{
						URI: `pg-functions://postgres/auth/` +
							`v0hooks_test_password_verification_attempt`,
						HookName: `"auth"."v0hooks_test_password_verification_attempt"`,
					}
			},
			req: &PasswordVerificationAttemptInput{
				UserID: testUUID,
				Valid:  true,
			},
			res: &PasswordVerificationAttemptOutput{},
			exp: &PasswordVerificationAttemptOutput{
				Decision: "reject",
				Message:  "Too many password attempts.",
			},
			sql: `
				create or replace function
					v0hooks_test_password_verification_attempt(input jsonb)
				returns json as $$
				begin
					return '{"decision":"reject","message":"Too many password attempts."}'::jsonb;
				end; $$ language plpgsql;`,
		},

		{
			desc: "pass - customize_access_token",
			setup: func() {
				globalCfg.Hook.CustomAccessToken =
					conf.ExtensibilityPointConfiguration{
						URI: `pg-functions://postgres/auth/` +
							`v0hooks_test_customize_access_token`,
						HookName: `"auth"."v0hooks_test_customize_access_token"`,
					}
			},
			req: &CustomAccessTokenInput{
				Claims: &AccessTokenClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						Audience:  []string{"myaudience"},
						Issuer:    "myissuer",
						ExpiresAt: jwt.NewNumericDate(now),
						IssuedAt:  jwt.NewNumericDate(now),
						Subject:   "mysubject",
					},
					Email:                       "valid.email@supabase.co",
					AuthenticatorAssuranceLevel: "aal1",
					SessionId:                   "sid",
					Phone:                       "1234567890",
					UserMetaData:                M{"usermeta": "val1"},
					AppMetaData:                 M{"appmeta": "val2"},
					Role:                        "myrole",
				},
			},
			res: &CustomAccessTokenOutput{},
			exp: &CustomAccessTokenOutput{
				Claims: M{
					"aud":           []interface{}{"myaudience"},
					"iss":           "myissuer",
					"email":         "valid.email@supabase.co",
					"exp":           1.7040672e+09,
					"iat":           1.7040672e+09,
					"sub":           "mysubject",
					"aal":           "aal1",
					"session_id":    "sid",
					"is_anonymous":  false,
					"phone":         "1234567890",
					"user_metadata": M{"usermeta": "val1"},
					"app_metadata":  M{"appmeta": "val2"},
					"custom_claim":  "custom_value",
					"role":          "myrole",
				},
			},
			sql: `
				create or replace function
					v0hooks_test_customize_access_token(input jsonb)
				 returns json as $$
				 	declare
						claims jsonb;
					begin
						claims := input->'claims' || '{"custom_claim": "custom_value"}'::jsonb;
						return jsonb_build_object('claims', claims);
					end;
				$$ language plpgsql;`,
		},

		// fail
		{
			desc: "fail - customize_access_token - error propagation",
			setup: func() {
				globalCfg.Hook.CustomAccessToken =
					conf.ExtensibilityPointConfiguration{
						URI: `pg-functions://postgres/auth/` +
							`v0hooks_test_customize_access_token_failure`,
						HookName: `"auth"."v0hooks_test_customize_access_token_failure"`,
					}
			},
			req:    &CustomAccessTokenInput{},
			res:    &CustomAccessTokenOutput{},
			errStr: "500: failed hook",
			sql: `
				create or replace function
					v0hooks_test_customize_access_token_failure(input jsonb)
				returns json as $$
				begin
					return '{"error": {"message": "failed hook"}}'::jsonb;
				end; $$ language plpgsql;`,
		},

		{
			desc: "fail - customize_access_token - error propagation http code",
			setup: func() {
				globalCfg.Hook.CustomAccessToken =
					conf.ExtensibilityPointConfiguration{
						URI: `pg-functions://postgres/auth/` +
							`v0hooks_test_customize_access_token_failure`,
						HookName: `"auth"."v0hooks_test_customize_access_token_failure"`,
					}
			},
			req:    &CustomAccessTokenInput{},
			res:    &CustomAccessTokenOutput{},
			errStr: "403: auth failure",
			sql: `
				create or replace function
					v0hooks_test_customize_access_token_failure(input jsonb)
				returns json as $$
				begin
					return '{"error": {"message": "auth failure", "http_code": 403}}'::jsonb;
				end; $$ language plpgsql;`,
		},

		// fail - invalid URI type
		{
			desc: "fail - password_verification_attempt - run hook failure",
			setup: func() {
				globalCfg.Hook.PasswordVerificationAttempt =
					conf.ExtensibilityPointConfiguration{
						URI: `invalid://path/`,
					}
			},
			req:    &PasswordVerificationAttemptInput{},
			res:    &PasswordVerificationAttemptOutput{},
			errStr: "unsupported protocol:",
		},

		// fail - invalid input type
		{
			desc:   "fail - invalid intput type",
			req:    make(chan int),
			res:    M{},
			errStr: "500: Unknown hook type chan int.",
		},

		// fail - invalid output types
		{
			desc:   "fail - customize_access_token - invalid output type",
			req:    &CustomAccessTokenInput{},
			res:    M{},
			errStr: "500: output should be *hooks.CustomAccessTokenOutput",
		},
		{
			desc:   "fail - send_sms - invalid output type",
			req:    &SendSMSInput{},
			res:    M{},
			errStr: "500: output should be *hooks.SendSMSOutput",
		},
		{
			desc:   "fail - send_email - invalid output type",
			req:    &SendEmailInput{},
			res:    M{},
			errStr: "500: output should be *hooks.SendEmailOutput",
		},
		{
			desc:   "fail - mfa_verification_attempt - invalid output type",
			req:    &MFAVerificationAttemptInput{},
			res:    M{},
			errStr: "500: output should be *hooks.MFAVerificationAttemptOutput",
		},
		{
			desc:   "fail - password_verification_attempt - invalid output type",
			req:    &PasswordVerificationAttemptInput{},
			res:    M{},
			errStr: "500: output should be *hooks.PasswordVerificationAttemptOutput",
		},

		// fail - invalid query
		{
			desc: "fail - customize_access_token - run hook failure",
			setup: func() {
				globalCfg.Hook.CustomAccessToken =
					conf.ExtensibilityPointConfiguration{
						URI: `pg-functions://postgres/auth/` +
							`v0hooks_test_pgfunc_not_exists`,
						HookName: `"auth"."v0hooks_test_pgfunc_not_exists"`,
					}
			},
			req:    &CustomAccessTokenInput{},
			res:    &CustomAccessTokenOutput{},
			errStr: "500: Error running hook URI",
		},
		{
			desc: "fail - send_sms -run hook failure",
			setup: func() {
				globalCfg.Hook.SendSMS =
					conf.ExtensibilityPointConfiguration{
						URI: `pg-functions://postgres/auth/` +
							`v0hooks_test_pgfunc_not_exists`,
						HookName: `"auth"."v0hooks_test_pgfunc_not_exists"`,
					}
			},
			req:    &SendSMSInput{},
			res:    &SendSMSOutput{},
			errStr: "500: Error running hook URI",
		},
		{
			desc: "fail - send_email - run hook failure",
			setup: func() {
				globalCfg.Hook.SendEmail =
					conf.ExtensibilityPointConfiguration{
						URI: `pg-functions://postgres/auth/` +
							`v0hooks_test_pgfunc_not_exists`,
						HookName: `"auth"."v0hooks_test_pgfunc_not_exists"`,
					}
			},
			req:    &SendEmailInput{},
			res:    &SendEmailOutput{},
			errStr: "500: Error running hook URI",
		},
		{
			desc: "fail - mfa_verification_attempt - run hook failure",
			setup: func() {
				globalCfg.Hook.MFAVerificationAttempt =
					conf.ExtensibilityPointConfiguration{
						URI: `pg-functions://postgres/auth/` +
							`v0hooks_test_pgfunc_not_exists`,
						HookName: `"auth"."v0hooks_test_pgfunc_not_exists"`,
					}
			},
			req:    &MFAVerificationAttemptInput{},
			res:    &MFAVerificationAttemptOutput{},
			errStr: "500: Error running hook URI",
		},
		{
			desc: "fail - password_verification_attempt - run hook failure",
			setup: func() {
				globalCfg.Hook.PasswordVerificationAttempt =
					conf.ExtensibilityPointConfiguration{
						URI: `pg-functions://postgres/auth/` +
							`v0hooks_test_pgfunc_not_exists`,
						HookName: `"auth"."v0hooks_test_pgfunc_not_exists"`,
					}
			},
			req:    &PasswordVerificationAttemptInput{},
			res:    &PasswordVerificationAttemptOutput{},
			errStr: "500: Error running hook URI",
		},
	}

	for idx, tc := range cases {
		t.Logf("test #%v - %v", idx, tc.desc)

		sql := tc.sql
		if sql != "" {
			if err := db.RawQuery(sql).Exec(); err != nil {
				t.Fatalf("exp nil err; got %v", err)
			}
		}
		if tc.setup != nil {
			tc.setup()
		}

		htr := httptest.NewRequestWithContext(ctx, "POST", "/api", nil)
		err := mr.InvokeHook(db, htr, tc.req, tc.res)
		if tc.errStr != "" {
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.errStr)
			continue
		}
		require.NoError(t, err)
		require.Equal(t, tc.exp, tc.res)
	}
}

func TestConfig(t *testing.T) {
	globalCfg := &conf.GlobalConfiguration{
		Hook: conf.HookConfiguration{
			SendSMS: conf.ExtensibilityPointConfiguration{
				URI: "http:localhost/" + string(SendSMS),
			},
			SendEmail: conf.ExtensibilityPointConfiguration{
				URI: "http:localhost/" + string(SendEmail),
			},
			CustomAccessToken: conf.ExtensibilityPointConfiguration{
				URI: "http:localhost/" + string(CustomizeAccessToken),
			},
			MFAVerificationAttempt: conf.ExtensibilityPointConfiguration{
				URI: "http:localhost/" + string(MFAVerification),
			},
			PasswordVerificationAttempt: conf.ExtensibilityPointConfiguration{
				URI: "http:localhost/" + string(PasswordVerification),
			},
			BeforeUserCreated: conf.ExtensibilityPointConfiguration{
				URI: "http:localhost/" + string(BeforeUserCreated),
			},
			AfterUserCreated: conf.ExtensibilityPointConfiguration{
				URI: "http:localhost/" + string(AfterUserCreated),
			},
		},
	}
	cfg := &globalCfg.Hook

	mr := new(Manager)
	mr.config = globalCfg

	tests := []struct {
		cfg  *conf.HookConfiguration
		name Name
		exp  *conf.ExtensibilityPointConfiguration
		ok   bool
	}{
		{},
		{cfg: cfg, ok: true,
			name: SendSMS, exp: &cfg.SendSMS},
		{cfg: cfg, ok: true,
			name: SendEmail, exp: &cfg.SendEmail},
		{cfg: cfg, ok: true,
			name: CustomizeAccessToken, exp: &cfg.CustomAccessToken},
		{cfg: cfg, ok: true,
			name: MFAVerification, exp: &cfg.MFAVerificationAttempt},
		{cfg: cfg, ok: true,
			name: PasswordVerification, exp: &cfg.PasswordVerificationAttempt},
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

func TestUserHooks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	t.Run("BeforeUserCreated", func(t *testing.T) {
		httpReq := httptest.NewRequest("GET", "http://localhost/test", nil)
		user := &models.User{}
		req := NewBeforeUserCreatedRequest(httpReq, user)
		res := new(BeforeUserCreatedResponse)

		t.Run("BeforeUserCreatedSuccess", func(t *testing.T) {
			cfg := e2e.Must(e2e.Config())
			dr := newMockService(nil)
			mr := &Manager{config: cfg, dr: dr}

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
			cfg := e2e.Must(e2e.Config())
			sentinel := errors.New("sentinel")
			dr := newMockService(sentinel)
			mr := &Manager{config: cfg, dr: dr}

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
			cfg := e2e.Must(e2e.Config())
			dr := newMockService(nil)
			mr := &Manager{config: cfg, dr: dr}

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
			cfg := e2e.Must(e2e.Config())
			sentinel := errors.New("sentinel")
			dr := newMockService(sentinel)
			mr := &Manager{config: cfg, dr: dr}

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

type mockCall struct {
	conn          *storage.Connection
	hookConfig    *conf.ExtensibilityPointConfiguration
	input, output any
}

type mockDispatcher struct {
	mu    sync.Mutex
	err   error
	calls []*mockCall
}

func newMockService(err error) *mockDispatcher { return &mockDispatcher{err: err} }

func (o *mockDispatcher) dispatch(
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
