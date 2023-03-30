package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	jwt "github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/gotrue/internal/conf"
)

const (
	HCaptchaSecret   string = "0x0000000000000000000000000000000000000000"
	HCaptchaResponse string = "10000000-aaaa-bbbb-cccc-000000000001"
)

type MiddlewareTestSuite struct {
	suite.Suite
	API    *API
	Config *conf.GlobalConfiguration
}

func TestMiddlewareFunctions(t *testing.T) {
	api, config, err := setupAPIForTest()
	require.NoError(t, err)

	ts := &MiddlewareTestSuite{
		API:    api,
		Config: config,
	}
	defer api.db.Close()

	suite.Run(t, ts)
}

func (ts *MiddlewareTestSuite) TestVerifyCaptchaValid() {
	ts.Config.Security.Captcha.Enabled = true
	ts.Config.Security.Captcha.Provider = "hcaptcha"
	ts.Config.Security.Captcha.Secret = HCaptchaSecret

	adminClaims := &GoTrueClaims{
		Role: "supabase_admin",
	}
	adminJwt, err := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims).SignedString([]byte(ts.Config.JWT.Secret))
	require.NoError(ts.T(), err)
	cases := []struct {
		desc          string
		adminJwt      string
		captcha_token string
	}{
		{
			"Valid captcha response",
			"",
			HCaptchaResponse,
		},
		{
			"Ignore captcha if admin role is present",
			adminJwt,
			"",
		},
	}
	for _, c := range cases {
		var buffer bytes.Buffer
		require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
			"email":    "test@example.com",
			"password": "secret",
			"gotrue_meta_security": map[string]interface{}{
				"captcha_token": c.captcha_token,
			},
		}))
		req := httptest.NewRequest(http.MethodPost, "http://localhost", &buffer)
		req.Header.Set("Content-Type", "application/json")
		if c.adminJwt != "" {
			req.Header.Set("Authorization", "Bearer "+c.adminJwt)
		}

		beforeCtx := context.Background()
		req = req.WithContext(beforeCtx)

		w := httptest.NewRecorder()

		afterCtx, err := ts.API.verifyCaptcha(w, req)
		require.NoError(ts.T(), err)

		body, err := io.ReadAll(req.Body)
		require.NoError(ts.T(), err)

		// re-initialize buffer
		require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
			"email":    "test@example.com",
			"password": "secret",
			"gotrue_meta_security": map[string]interface{}{
				"captcha_token": c.captcha_token,
			},
		}))

		// check if body is the same
		require.Equal(ts.T(), body, buffer.Bytes())
		require.Equal(ts.T(), afterCtx, beforeCtx)
	}
}

func (ts *MiddlewareTestSuite) TestVerifyCaptchaInvalid() {
	cases := []struct {
		desc         string
		captchaConf  *conf.CaptchaConfiguration
		expectedCode int
		expectedMsg  string
	}{
		{
			"Captcha validation failed",
			&conf.CaptchaConfiguration{
				Enabled:  true,
				Provider: "hcaptcha",
				Secret:   "test",
			},
			http.StatusBadRequest,
			"hCaptcha protection: request disallowed (not-using-dummy-secret)",
		},
	}
	for _, c := range cases {
		ts.Run(c.desc, func() {
			ts.Config.Security.Captcha = *c.captchaConf
			var buffer bytes.Buffer
			require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
				"email":    "test@example.com",
				"password": "secret",
				"gotrue_meta_security": map[string]interface{}{
					"captcha_token": HCaptchaResponse,
				},
			}))
			req := httptest.NewRequest(http.MethodPost, "http://localhost", &buffer)
			req.Header.Set("Content-Type", "application/json")

			req = req.WithContext(context.Background())

			w := httptest.NewRecorder()

			_, err := ts.API.verifyCaptcha(w, req)
			require.Equal(ts.T(), c.expectedCode, err.(*HTTPError).Code)
			require.Equal(ts.T(), c.expectedMsg, err.(*HTTPError).Message)
		})
	}
}

func (ts *MiddlewareTestSuite) TestLimitEmailOrPhoneSentHandler() {
	// Set up rate limit config for this test
	ts.Config.RateLimitEmailSent = 5
	ts.Config.RateLimitSmsSent = 5

	cases := []struct {
		desc             string
		expectedErrorMsg string
		requestBody      map[string]interface{}
	}{
		{
			desc:             "Email rate limit exceeded",
			expectedErrorMsg: "429: Email rate limit exceeded",
			requestBody: map[string]interface{}{
				"email": "test@example.com",
			},
		},
		{
			desc:             "Sms rate limit exceeded",
			expectedErrorMsg: "429: Sms rate limit exceeded",
			requestBody: map[string]interface{}{
				"phone": "+1233456789",
			},
		},
	}

	limiter := ts.API.limitEmailOrPhoneSentHandler()
	for _, c := range cases {
		ts.Run(c.desc, func() {
			var buffer bytes.Buffer
			require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(c.requestBody))
			req := httptest.NewRequest(http.MethodPost, "http://localhost", &buffer)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			for i := 0; i < 5; i++ {
				_, err := limiter(w, req)
				require.NoError(ts.T(), err)
			}

			// should exceed rate limit on 5th try
			_, err := limiter(w, req)
			require.Error(ts.T(), err)
			require.Equal(ts.T(), c.expectedErrorMsg, err.Error())
		})
	}
}

func (ts *MiddlewareTestSuite) TestRequireSAMLEnabled() {
	cases := []struct {
		desc        string
		isEnabled   bool
		expectedErr error
	}{
		{
			desc:        "SAML not enabled",
			isEnabled:   false,
			expectedErr: notFoundError("SAML 2.0 is disabled"),
		},
		{
			desc:        "SAML enabled",
			isEnabled:   true,
			expectedErr: nil,
		},
	}

	for _, c := range cases {
		ts.Run(c.desc, func() {
			ts.Config.SAML.Enabled = c.isEnabled
			req := httptest.NewRequest("GET", "http://localhost", nil)
			w := httptest.NewRecorder()

			_, err := ts.API.requireSAMLEnabled(w, req)
			require.Equal(ts.T(), c.expectedErr, err)
		})
	}
}

func TestFunctionHooksUnmarshalJSON(t *testing.T) {
	tests := []struct {
		in string
		ok bool
	}{
		{`{ "signup" : "identity-signup" }`, true},
		{`{ "signup" : ["identity-signup"] }`, true},
		{`{ "signup" : {"foo" : "bar"} }`, false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			var f FunctionHooks
			err := json.Unmarshal([]byte(tt.in), &f)
			if tt.ok {
				assert.NoError(t, err)
				assert.Equal(t, FunctionHooks{"signup": {"identity-signup"}}, f)
			} else {
				assert.Error(t, err)
			}
		})
	}
}
