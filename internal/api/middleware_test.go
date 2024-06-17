package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/didip/tollbooth/v5"
	"github.com/didip/tollbooth/v5/limiter"
	jwt "github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/conf"
)

const (
	HCaptchaSecret         string = "0x0000000000000000000000000000000000000000"
	CaptchaResponse        string = "10000000-aaaa-bbbb-cccc-000000000001"
	TurnstileCaptchaSecret string = "1x0000000000000000000000000000000AA"
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

	adminClaims := &AccessTokenClaims{
		Role: "supabase_admin",
	}
	adminJwt, err := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims).SignedString([]byte(ts.Config.JWT.Secret))
	require.NoError(ts.T(), err)
	cases := []struct {
		desc             string
		adminJwt         string
		captcha_token    string
		captcha_provider string
	}{
		{
			"Valid captcha response",
			"",
			CaptchaResponse,
			"hcaptcha",
		},
		{
			"Valid captcha response",
			"",
			CaptchaResponse,
			"turnstile",
		},
		{
			"Ignore captcha if admin role is present",
			adminJwt,
			"",
			"hcaptcha",
		},
		{
			"Ignore captcha if admin role is present",
			adminJwt,
			"",
			"turnstile",
		},
	}
	for _, c := range cases {
		ts.Config.Security.Captcha.Provider = c.captcha_provider
		if c.captcha_provider == "turnstile" {
			ts.Config.Security.Captcha.Secret = TurnstileCaptchaSecret
		} else if c.captcha_provider == "hcaptcha" {
			ts.Config.Security.Captcha.Secret = HCaptchaSecret
		}

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
			"captcha protection: request disallowed (not-using-dummy-secret)",
		},
		{
			"Captcha validation failed",
			&conf.CaptchaConfiguration{
				Enabled:  true,
				Provider: "turnstile",
				Secret:   "anothertest",
			},
			http.StatusBadRequest,
			"captcha protection: request disallowed (invalid-input-secret)",
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
					"captcha_token": CaptchaResponse,
				},
			}))
			req := httptest.NewRequest(http.MethodPost, "http://localhost", &buffer)
			req.Header.Set("Content-Type", "application/json")

			req = req.WithContext(context.Background())

			w := httptest.NewRecorder()

			_, err := ts.API.verifyCaptcha(w, req)
			require.Equal(ts.T(), c.expectedCode, err.(*HTTPError).HTTPStatus)
			require.Equal(ts.T(), c.expectedMsg, err.(*HTTPError).Message)
		})
	}
}

func (ts *MiddlewareTestSuite) TestLimitEmailOrPhoneSentHandler() {
	// Set up rate limit config for this test
	ts.Config.RateLimitEmailSent = 5
	ts.Config.RateLimitSmsSent = 5
	ts.Config.External.Phone.Enabled = true

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
			desc:             "SMS rate limit exceeded",
			expectedErrorMsg: "429: SMS rate limit exceeded",
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

func (ts *MiddlewareTestSuite) TestIsValidExternalHost() {
	cases := []struct {
		desc        string
		requestURL  string
		expectedURL string
	}{
		{
			desc:        "Valid custom external url",
			requestURL:  "https://example.custom.com",
			expectedURL: "https://example.custom.com",
		},
	}

	_, err := url.ParseRequestURI("https://example.custom.com")
	require.NoError(ts.T(), err)

	for _, c := range cases {
		ts.Run(c.desc, func() {
			req := httptest.NewRequest(http.MethodPost, c.requestURL, nil)
			w := httptest.NewRecorder()
			ctx, err := ts.API.isValidExternalHost(w, req)
			require.NoError(ts.T(), err)

			externalURL := getExternalHost(ctx)
			require.Equal(ts.T(), c.expectedURL, externalURL.String())
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
			expectedErr: notFoundError(ErrorCodeSAMLProviderDisabled, "SAML 2.0 is disabled"),
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

func (ts *MiddlewareTestSuite) TestTimeoutMiddleware() {
	ts.Config.API.MaxRequestDuration = 5 * time.Microsecond
	req := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
	w := httptest.NewRecorder()

	timeoutHandler := timeoutMiddleware(ts.Config.API.MaxRequestDuration)

	slowHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Sleep for 1 second to simulate a slow handler which should trigger the timeout
		time.Sleep(1 * time.Second)
		ts.API.handler.ServeHTTP(w, r)
	})
	timeoutHandler(slowHandler).ServeHTTP(w, req)
	assert.Equal(ts.T(), http.StatusGatewayTimeout, w.Code)

	var data map[string]interface{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))
	require.Equal(ts.T(), ErrorCodeRequestTimeout, data["error_code"])
	require.Equal(ts.T(), float64(504), data["code"])
	require.NotNil(ts.T(), data["msg"])
}

func TestTimeoutResponseWriter(t *testing.T) {
	// timeoutResponseWriter should exhitbit a similar behavior as http.ResponseWriter
	req := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
	w1 := httptest.NewRecorder()
	w2 := httptest.NewRecorder()

	timeoutHandler := timeoutMiddleware(time.Second * 10)

	redirectHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// tries to redirect twice
		http.Redirect(w, r, "http://localhost:3001/#message=first_message", http.StatusSeeOther)

		// overwrites the first
		http.Redirect(w, r, "http://localhost:3001/second", http.StatusSeeOther)
	})
	timeoutHandler(redirectHandler).ServeHTTP(w1, req)
	redirectHandler.ServeHTTP(w2, req)

	require.Equal(t, w1.Result(), w2.Result())
}

func (ts *MiddlewareTestSuite) TestLimitHandler() {
	ts.Config.RateLimitHeader = "X-Rate-Limit"
	lmt := tollbooth.NewLimiter(5, &limiter.ExpirableOptions{
		DefaultExpirationTTL: time.Hour,
	})

	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		b, _ := json.Marshal(map[string]interface{}{"message": "ok"})
		w.Write([]byte(b))
	})

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
		req.Header.Add(ts.Config.RateLimitHeader, "0.0.0.0")
		w := httptest.NewRecorder()
		ts.API.limitHandler(lmt).handler(okHandler).ServeHTTP(w, req)
		require.Equal(ts.T(), http.StatusOK, w.Code)

		var data map[string]interface{}
		require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))
		require.Equal(ts.T(), "ok", data["message"])
	}

	// 6th request should fail and return a rate limit exceeded error
	req := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
	req.Header.Add(ts.Config.RateLimitHeader, "0.0.0.0")
	w := httptest.NewRecorder()
	ts.API.limitHandler(lmt).handler(okHandler).ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusTooManyRequests, w.Code)
}

func (ts *MiddlewareTestSuite) TestLimitHandlerWithSharedLimiter() {
	// setup config for shared limiter and ip-based limiter to work
	ts.Config.RateLimitHeader = "X-Rate-Limit"
	ts.Config.External.Email.Enabled = true
	ts.Config.External.Phone.Enabled = true
	ts.Config.Mailer.Autoconfirm = false
	ts.Config.Sms.Autoconfirm = false

	ipBasedLimiter := func(max float64) *limiter.Limiter {
		return tollbooth.NewLimiter(max, &limiter.ExpirableOptions{
			DefaultExpirationTTL: time.Hour,
		})
	}

	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	cases := []struct {
		desc                 string
		sharedLimiterConfig  *conf.GlobalConfiguration
		ipBasedLimiterConfig float64
		body                 map[string]interface{}
		expectedErrorCode    string
	}{
		{
			desc: "Exceed ip-based rate limit before shared limiter",
			sharedLimiterConfig: &conf.GlobalConfiguration{
				RateLimitEmailSent: 10,
				RateLimitSmsSent:   10,
			},
			ipBasedLimiterConfig: 1,
			body: map[string]interface{}{
				"email": "foo@example.com",
			},
			expectedErrorCode: ErrorCodeOverRequestRateLimit,
		},
		{
			desc: "Exceed email shared limiter",
			sharedLimiterConfig: &conf.GlobalConfiguration{
				RateLimitEmailSent: 1,
				RateLimitSmsSent:   1,
			},
			ipBasedLimiterConfig: 10,
			body: map[string]interface{}{
				"email": "foo@example.com",
			},
			expectedErrorCode: ErrorCodeOverEmailSendRateLimit,
		},
		{
			desc: "Exceed sms shared limiter",
			sharedLimiterConfig: &conf.GlobalConfiguration{
				RateLimitEmailSent: 1,
				RateLimitSmsSent:   1,
			},
			ipBasedLimiterConfig: 10,
			body: map[string]interface{}{
				"phone": "123456789",
			},
			expectedErrorCode: ErrorCodeOverSMSSendRateLimit,
		},
	}

	for _, c := range cases {
		ts.Run(c.desc, func() {
			ts.Config.RateLimitEmailSent = c.sharedLimiterConfig.RateLimitEmailSent
			ts.Config.RateLimitSmsSent = c.sharedLimiterConfig.RateLimitSmsSent
			lmt := ts.API.limitHandler(ipBasedLimiter(c.ipBasedLimiterConfig))
			sharedLimiter := ts.API.limitEmailOrPhoneSentHandler()

			// get the minimum amount to reach the threshold just before the rate limit is exceeded
			threshold := min(c.sharedLimiterConfig.RateLimitEmailSent, c.sharedLimiterConfig.RateLimitSmsSent, c.ipBasedLimiterConfig)
			for i := 0; i < int(threshold); i++ {
				var buffer bytes.Buffer
				require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(c.body))
				req := httptest.NewRequest(http.MethodPost, "http://localhost", &buffer)
				req.Header.Add(ts.Config.RateLimitHeader, "0.0.0.0")

				w := httptest.NewRecorder()
				lmt.handler(sharedLimiter.handler(okHandler)).ServeHTTP(w, req)
				require.Equal(ts.T(), http.StatusOK, w.Code)
			}

			var buffer bytes.Buffer
			require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(c.body))
			req := httptest.NewRequest(http.MethodPost, "http://localhost", &buffer)
			req.Header.Add(ts.Config.RateLimitHeader, "0.0.0.0")

			// check if the rate limit is exceeded with the expected error code
			w := httptest.NewRecorder()
			lmt.handler(sharedLimiter.handler(okHandler)).ServeHTTP(w, req)
			require.Equal(ts.T(), http.StatusTooManyRequests, w.Code)

			var data map[string]interface{}
			require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))
			require.Equal(ts.T(), c.expectedErrorCode, data["error_code"])
		})
	}
}
