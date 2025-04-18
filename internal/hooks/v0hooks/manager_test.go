package v0hooks

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/hooks/v0hooks/v0http"
	"github.com/supabase/auth/internal/hooks/v0hooks/v0pgfunc"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/storage/test"
)

type M = map[string]any

var testUUID = uuid.Must(uuid.FromString(
	"00000000-0000-0000-0000-000000000000"))

func TestHooks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	globalCfg := helpConfig(t, apiTestConfig)
	db := helpConn(t, globalCfg)
	httpDr := v0http.New(v0http.WithTimeout(time.Second / 10))
	pgfuncDr := v0pgfunc.New(db, v0pgfunc.WithTimeout(time.Second/10))
	mr := NewManager(globalCfg, httpDr, pgfuncDr)
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

	// Cover auth hook errors single method
	{
		ae := &AuthHookError{Message: "test"}
		if exp, got := "test", ae.Error(); exp != got {
			t.Fatalf("exp %v; got %v", exp, got)
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
			errStr: "500: Error running hook URI: http://0.0.0.0:12345",
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

		// fail - missing required claims
		{
			desc: "fail - customize_access_token - missing required claims",
			setup: func() {
				globalCfg.Hook.CustomAccessToken =
					conf.ExtensibilityPointConfiguration{
						URI: `pg-functions://postgres/auth/` +
							`v0hooks_test_customize_access_token_fail_missing`,
						HookName: `"auth"."v0hooks_test_customize_access_token_fail_missing"`,
					}
			},
			req: &CustomAccessTokenInput{
				Claims: &AccessTokenClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						Audience:  []string{"myaudience"},
						ExpiresAt: jwt.NewNumericDate(now),
						IssuedAt:  jwt.NewNumericDate(now),
						Subject:   "mysubject",
					},
					Email:                       "valid.email@supabase.co",
					AuthenticatorAssuranceLevel: "aal1",
					SessionId:                   "sid",
					Phone:                       "1234567890",
					AppMetaData:                 M{"appmeta": "val2"},
					Role:                        "myrole",
				},
			},
			res: &CustomAccessTokenOutput{},
			exp: &CustomAccessTokenOutput{
				Claims: M{
					"aud":          []interface{}{"myaudience"},
					"email":        "valid.email@supabase.co",
					"exp":          1.7040672e+09,
					"iat":          1.7040672e+09,
					"sub":          "mysubject",
					"aal":          "aal1",
					"session_id":   "sid",
					"is_anonymous": false,
					"phone":        "1234567890",
					"app_metadata": M{"appmeta": "val2"},
					"custom_claim": "custom_value",
					"role":         "myrole",
				},
			},
			sql: `
				create or replace function
					v0hooks_test_customize_access_token_fail_missing(input jsonb)
				 returns json as $$
				 	declare
						claims jsonb;
					begin
						claims := input->'claims' || '{"custom_claim": "custom_value"}'::jsonb;
						return jsonb_build_object('claims', claims);
					end;
				$$ language plpgsql;`,
			errStr: "500: output claims do not conform to the expected schema",
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
			req: &CustomAccessTokenInput{},
			res: &CustomAccessTokenOutput{},
			exp: &CustomAccessTokenOutput{
				HookError: AuthHookError{
					Message: "failed hook",
				},
			},
			errStr: "500: failed hook",
			sql: `
				create or replace function
					v0hooks_test_customize_access_token_failure(input jsonb)
				returns json as $$
				begin
					return '{"error": {"message": "failed hook"}}'::jsonb;
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

		if h, ok := tc.res.(HookOutput); ok {
			_ = h.Error()
			_ = h.GetHookError()
			_ = h.IsError()
		}
	}
}

const (
	apiTestConfig = "../../../hack/test.env"
)

func helpConfig(t testing.TB, configPath string) *conf.GlobalConfiguration {
	t.Helper()

	config, err := conf.LoadGlobal(configPath)
	if err != nil {
		t.Fatalf("error loading config %q; got %v", configPath, err)
	}
	return config
}

func helpConn(t testing.TB, config *conf.GlobalConfiguration) *storage.Connection {
	t.Helper()

	conn, err := test.SetupDBConnection(config)
	if err != nil {
		t.Fatalf("error setting up db connection: %v", err)
	}
	return conn
}
