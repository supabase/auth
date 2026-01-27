package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gobwas/glob"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/crypto"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

type MailTestSuite struct {
	suite.Suite
	API    *API
	Config *conf.GlobalConfiguration
}

func TestMail(t *testing.T) {
	api, config, err := setupAPIForTest()
	require.NoError(t, err)

	ts := &MailTestSuite{
		API:    api,
		Config: config,
	}
	defer api.db.Close()

	suite.Run(t, ts)
}

func (ts *MailTestSuite) SetupTest() {
	models.TruncateAll(ts.API.db)

	ts.Config.Mailer.SecureEmailChangeEnabled = true

	// Create User
	u, err := models.NewUser("12345678", "test@example.com", "password", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err, "Error creating new user model")
	require.NoError(ts.T(), ts.API.db.Create(u), "Error saving new user")
}

func (ts *MailTestSuite) TestValidateEmail() {
	cases := []struct {
		desc          string
		email         string
		expectedEmail string
		expectedError error
	}{
		{
			desc:          "valid email",
			email:         "test@example.com",
			expectedEmail: "test@example.com",
			expectedError: nil,
		},
		{
			desc:          "email should be normalized",
			email:         "TEST@EXAMPLE.COM",
			expectedEmail: "test@example.com",
			expectedError: nil,
		},
		{
			desc:          "empty email should return error",
			email:         "",
			expectedEmail: "",
			expectedError: apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "An email address is required"),
		},
		{
			desc: "email length exceeds 255 characters",
			// email has 256 characters
			email:         "testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest@example.com",
			expectedEmail: "",
			expectedError: apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "An email address is too long"),
		},
	}

	for _, c := range cases {
		ts.Run(c.desc, func() {
			email, err := ts.API.validateEmail(c.email)
			require.Equal(ts.T(), c.expectedError, err)
			require.Equal(ts.T(), c.expectedEmail, email)
		})
	}
}

func (ts *MailTestSuite) TestGenerateLink() {
	// create admin jwt
	claims := &AccessTokenClaims{
		Role: "supabase_admin",
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(ts.Config.JWT.Secret))
	require.NoError(ts.T(), err, "Error generating admin jwt")

	ts.setURIAllowListMap("http://localhost:8000/**")
	// create test cases
	cases := []struct {
		Desc             string
		Body             GenerateLinkParams
		ExpectedCode     int
		ExpectedResponse map[string]interface{}
	}{
		{
			Desc: "Generate signup link for new user",
			Body: GenerateLinkParams{
				Email:    "new_user@example.com",
				Password: "secret123",
				Type:     "signup",
			},
			ExpectedCode: http.StatusOK,
			ExpectedResponse: map[string]interface{}{
				"redirect_to": ts.Config.SiteURL,
			},
		},
		{
			Desc: "Generate signup link for existing user",
			Body: GenerateLinkParams{
				Email:    "test@example.com",
				Password: "secret123",
				Type:     "signup",
			},
			ExpectedCode: http.StatusOK,
			ExpectedResponse: map[string]interface{}{
				"redirect_to": ts.Config.SiteURL,
			},
		},
		{
			Desc: "Generate signup link with custom redirect url",
			Body: GenerateLinkParams{
				Email:      "test@example.com",
				Password:   "secret123",
				Type:       "signup",
				RedirectTo: "http://localhost:8000/welcome",
			},
			ExpectedCode: http.StatusOK,
			ExpectedResponse: map[string]interface{}{
				"redirect_to": "http://localhost:8000/welcome",
			},
		},
		{
			Desc: "Generate magic link",
			Body: GenerateLinkParams{
				Email: "test@example.com",
				Type:  "magiclink",
			},
			ExpectedCode: http.StatusOK,
			ExpectedResponse: map[string]interface{}{
				"redirect_to": ts.Config.SiteURL,
			},
		},
		{
			Desc: "Generate invite link",
			Body: GenerateLinkParams{
				Email: "test@example.com",
				Type:  "invite",
			},
			ExpectedCode: http.StatusOK,
			ExpectedResponse: map[string]interface{}{
				"redirect_to": ts.Config.SiteURL,
			},
		},
		{
			Desc: "Generate recovery link",
			Body: GenerateLinkParams{
				Email: "test@example.com",
				Type:  "recovery",
			},
			ExpectedCode: http.StatusOK,
			ExpectedResponse: map[string]interface{}{
				"redirect_to": ts.Config.SiteURL,
			},
		},
		{
			Desc: "Generate email change link",
			Body: GenerateLinkParams{
				Email:    "test@example.com",
				NewEmail: "new@example.com",
				Type:     "email_change_current",
			},
			ExpectedCode: http.StatusOK,
			ExpectedResponse: map[string]interface{}{
				"redirect_to": ts.Config.SiteURL,
			},
		},
		{
			Desc: "Generate email change link",
			Body: GenerateLinkParams{
				Email:    "test@example.com",
				NewEmail: "new@example.com",
				Type:     "email_change_new",
			},
			ExpectedCode: http.StatusOK,
			ExpectedResponse: map[string]interface{}{
				"redirect_to": ts.Config.SiteURL,
			},
		},
	}

	customDomainUrl, err := url.ParseRequestURI("https://example.gotrue.com")
	require.NoError(ts.T(), err)

	originalHosts := ts.API.config.Mailer.ExternalHosts
	ts.API.config.Mailer.ExternalHosts = []string{
		"example.gotrue.com",
	}

	for _, c := range cases {
		ts.Run(c.Desc, func() {
			var buffer bytes.Buffer
			require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(c.Body))
			req := httptest.NewRequest(http.MethodPost, customDomainUrl.String()+"/admin/generate_link", &buffer)
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
			w := httptest.NewRecorder()

			ts.API.handler.ServeHTTP(w, req)

			require.Equal(ts.T(), c.ExpectedCode, w.Code)

			data := make(map[string]interface{})
			require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))

			require.Contains(ts.T(), data, "action_link")
			require.Contains(ts.T(), data, "email_otp")
			require.Contains(ts.T(), data, "hashed_token")
			require.Contains(ts.T(), data, "redirect_to")
			require.Equal(ts.T(), c.Body.Type, data["verification_type"])

			// check if redirect_to is correct
			require.Equal(ts.T(), c.ExpectedResponse["redirect_to"], data["redirect_to"])

			// check if hashed_token matches hash function of email and the raw otp
			require.Equal(ts.T(), crypto.GenerateTokenHash(c.Body.Email, data["email_otp"].(string)), data["hashed_token"])

			// check if the host used in the email link matches the initial request host
			u, err := url.ParseRequestURI(data["action_link"].(string))
			require.NoError(ts.T(), err)
			require.Equal(ts.T(), req.Host, u.Host)
		})
	}

	ts.API.config.Mailer.ExternalHosts = originalHosts
}

func (ts *MailTestSuite) setURIAllowListMap(uris ...string) {
	for _, uri := range uris {
		g := glob.MustCompile(uri, '.', '/')
		ts.Config.URIAllowListMap[uri] = g
	}
}

// mockLimiter is a test implementation of ratelimit.Limiter
type mockLimiter struct {
	allowFunc func() bool
}

func (m *mockLimiter) Allow() bool {
	if m.allowFunc != nil {
		return m.allowFunc()
	}
	return true
}

func (m *mockLimiter) AllowAt(at time.Time) bool {
	return m.Allow()
}

func (ts *MailTestSuite) TestSendEmailRateLimitingWithHook() {
	u, err := models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)

	// Enable the send email hook
	ts.Config.Hook.SendEmail.Enabled = true
	ts.Config.Mailer.Autoconfirm = false

	// Create a limiter that always returns false (would normally block)
	rateLimitExceeded := false
	mockLimiter := &mockLimiter{
		allowFunc: func() bool {
			rateLimitExceeded = true
			return false
		},
	}

	// Set up the API with the mock limiter
	originalLimiter := ts.API.limiterOpts.Email
	ts.API.limiterOpts.Email = mockLimiter
	defer func() {
		ts.API.limiterOpts.Email = originalLimiter
	}()

	// Create a request with proper context
	testURL, _ := url.Parse("http://localhost")
	req := httptest.NewRequest(http.MethodPost, "http://localhost", nil)
	ctx := req.Context()
	ctx = withExternalHost(ctx, testURL)
	req = req.WithContext(ctx)

	// Call sendConfirmation which internally calls sendEmail
	err = ts.API.db.Transaction(func(tx *storage.Connection) error {
		return ts.API.sendConfirmation(req, tx, u, models.ImplicitFlow)
	})

	// When hook is enabled, the hook should be invoked and rate limiting should be skipped
	// Since we don't have a real hook configured, it will return an error from hook invocation
	// But the important part is that rateLimitExceeded should remain false
	require.False(ts.T(), rateLimitExceeded, "Rate limiting check should be skipped when send email hook is enabled")
}

func (ts *MailTestSuite) TestSendEmailRateLimitingWithoutHook() {
	// Test that rate limiting is applied when send email hook is NOT enabled
	u, err := models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)

	// Disable the send email hook
	ts.Config.Hook.SendEmail.Enabled = false
	ts.Config.Mailer.Autoconfirm = false

	// Create a limiter that always returns false (blocks)
	rateLimitChecked := false
	mockLimiter := &mockLimiter{
		allowFunc: func() bool {
			rateLimitChecked = true
			return false
		},
	}

	// Set up the API with the mock limiter
	originalLimiter := ts.API.limiterOpts.Email
	ts.API.limiterOpts.Email = mockLimiter
	defer func() {
		ts.API.limiterOpts.Email = originalLimiter
	}()

	// Create a request with proper context
	testURL, _ := url.Parse("http://localhost")
	req := httptest.NewRequest(http.MethodPost, "http://localhost", nil)
	ctx := req.Context()
	ctx = withExternalHost(ctx, testURL)
	req = req.WithContext(ctx)

	// Call sendConfirmation which internally calls sendEmail
	err = ts.API.db.Transaction(func(tx *storage.Connection) error {
		return ts.API.sendConfirmation(req, tx, u, models.ImplicitFlow)
	})

	// Rate limiting should be checked and the request should be blocked
	require.True(ts.T(), rateLimitChecked, "Rate limiting check should be performed when send email hook is disabled")
	require.Error(ts.T(), err, "Should return an error when rate limit is exceeded")
	require.Contains(ts.T(), err.Error(), "email rate limit exceeded", "Error should indicate rate limit exceeded")
}
