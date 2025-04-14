package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/didip/tollbooth/v5"
	"github.com/didip/tollbooth/v5/limiter"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/storage"
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

func (ts *MiddlewareTestSuite) TestIsValidExternalHost() {
	cases := []struct {
		desc          string
		externalHosts []string

		requestURL string
		headers    http.Header

		expectedURL string
	}{
		{
			desc:        "no defined external hosts, no headers, no absolute request URL",
			requestURL:  "/some-path",
			expectedURL: ts.API.config.API.ExternalURL,
		},

		{
			desc: "no defined external hosts, unauthorized X-Forwarded-Host without any external hosts",
			headers: http.Header{
				"X-Forwarded-Host": []string{
					"external-host.com",
				},
			},
			requestURL:  "/some-path",
			expectedURL: ts.API.config.API.ExternalURL,
		},

		{
			desc:          "defined external hosts, unauthorized X-Forwarded-Host",
			externalHosts: []string{"authorized-host.com"},
			headers: http.Header{
				"X-Forwarded-Proto": []string{"https"},
				"X-Forwarded-Host": []string{
					"external-host.com",
				},
			},
			requestURL:  "/some-path",
			expectedURL: ts.API.config.API.ExternalURL,
		},

		{
			desc:        "no defined external hosts, unauthorized Host",
			requestURL:  "https://external-host.com/some-path",
			expectedURL: ts.API.config.API.ExternalURL,
		},

		{
			desc:          "defined external hosts, unauthorized Host",
			externalHosts: []string{"authorized-host.com"},
			requestURL:    "https://external-host.com/some-path",
			expectedURL:   ts.API.config.API.ExternalURL,
		},

		{
			desc:          "defined external hosts, authorized X-Forwarded-Host",
			externalHosts: []string{"authorized-host.com"},
			headers: http.Header{
				"X-Forwarded-Proto": []string{"http"}, // this should be ignored and default to HTTPS
				"X-Forwarded-Host": []string{
					"authorized-host.com",
				},
			},
			requestURL:  "https://X-Forwarded-Host-takes-precedence.com/some-path",
			expectedURL: "https://authorized-host.com",
		},

		{
			desc:          "defined external hosts, authorized Host",
			externalHosts: []string{"authorized-host.com"},
			requestURL:    "https://authorized-host.com/some-path",
			expectedURL:   "https://authorized-host.com",
		},

		{
			desc:          "defined external hosts, authorized X-Forwarded-Host",
			externalHosts: []string{"authorized-host.com"},
			headers: http.Header{
				"X-Forwarded-Proto": []string{"http"}, // this should be ignored and default to HTTPS
				"X-Forwarded-Host": []string{
					"authorized-host.com",
				},
			},
			requestURL:  "https://X-Forwarded-Host-takes-precedence.com/some-path",
			expectedURL: "https://authorized-host.com",
		},

		{
			desc:          "defined external hosts, authorized localhost in X-Forwarded-Host with HTTP",
			externalHosts: []string{"localhost"},
			headers: http.Header{
				"X-Forwarded-Proto": []string{"http"},
				"X-Forwarded-Host": []string{
					"localhost",
				},
			},
			requestURL:  "/some-path",
			expectedURL: "http://localhost",
		},

		{
			desc:          "defined external hosts, authorized localhost in Host with HTTP",
			externalHosts: []string{"localhost"},
			requestURL:    "http://localhost:3000/some-path",
			expectedURL:   "http://localhost",
		},
	}

	require.NotEmpty(ts.T(), ts.API.config.API.ExternalURL)

	for _, c := range cases {
		ts.Run(c.desc, func() {
			req := httptest.NewRequest(http.MethodPost, c.requestURL, nil)
			if c.headers != nil {
				req.Header = c.headers
			}

			originalHosts := ts.API.config.Mailer.ExternalHosts
			ts.API.config.Mailer.ExternalHosts = c.externalHosts

			w := httptest.NewRecorder()
			ctx, err := ts.API.isValidExternalHost(w, req)

			ts.API.config.Mailer.ExternalHosts = originalHosts

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
			expectedErr: apierrors.NewNotFoundError(apierrors.ErrorCodeSAMLProviderDisabled, "SAML 2.0 is disabled"),
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
	require.Equal(ts.T(), apierrors.ErrorCodeRequestTimeout, data["error_code"])
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

type MockCleanup struct {
	mock.Mock
}

func (m *MockCleanup) Clean(db *storage.Connection) (int, error) {
	m.Called(db)
	return 0, nil
}

func (ts *MiddlewareTestSuite) TestDatabaseCleanup() {
	testHandler := func(statusCode int) http.HandlerFunc {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(statusCode)
			b, _ := json.Marshal(map[string]interface{}{"message": "ok"})
			w.Write([]byte(b))
		})
	}

	cases := []struct {
		desc       string
		statusCode int
		method     string
	}{
		{
			desc:       "Run cleanup successfully",
			statusCode: http.StatusOK,
			method:     http.MethodPost,
		},
		{
			desc:       "Skip cleanup if GET",
			statusCode: http.StatusOK,
			method:     http.MethodGet,
		},
		{
			desc:       "Skip cleanup if 3xx",
			statusCode: http.StatusSeeOther,
			method:     http.MethodPost,
		},
		{
			desc:       "Skip cleanup if 4xx",
			statusCode: http.StatusBadRequest,
			method:     http.MethodPost,
		},
		{
			desc:       "Skip cleanup if 5xx",
			statusCode: http.StatusInternalServerError,
			method:     http.MethodPost,
		},
	}

	mockCleanup := new(MockCleanup)
	mockCleanup.On("Clean", mock.Anything).Return(0, nil)
	for _, c := range cases {
		ts.Run("DatabaseCleanup", func() {
			req := httptest.NewRequest(c.method, "http://localhost", nil)
			w := httptest.NewRecorder()
			ts.API.databaseCleanup(mockCleanup)(testHandler(c.statusCode)).ServeHTTP(w, req)
			require.Equal(ts.T(), c.statusCode, w.Code)
		})
	}
	mockCleanup.AssertNumberOfCalls(ts.T(), "Clean", 1)
}
