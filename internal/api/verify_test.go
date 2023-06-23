package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/gotrue/internal/conf"
	"github.com/supabase/gotrue/internal/models"
)

type VerifyTestSuite struct {
	suite.Suite
	API    *API
	Config *conf.GlobalConfiguration
}

func TestVerify(t *testing.T) {
	api, config, err := setupAPIForTest()
	require.NoError(t, err)

	ts := &VerifyTestSuite{
		API:    api,
		Config: config,
	}
	defer api.db.Close()

	suite.Run(t, ts)
}

func (ts *VerifyTestSuite) SetupTest() {
	models.TruncateAll(ts.API.db)

	// Create user
	u, err := models.NewUser("12345678", "test@example.com", "password", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err, "Error creating test user model")
	require.NoError(ts.T(), ts.API.db.Create(u), "Error saving new test user")
}

func (ts *VerifyTestSuite) TestVerifyPasswordRecovery() {
	// modify config so we don't hit rate limit from requesting recovery twice in 60s
	ts.Config.SMTP.MaxFrequency = 60
	u, err := models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	u.RecoverySentAt = &time.Time{}
	require.NoError(ts.T(), ts.API.db.Update(u))
	testEmail := "test@example.com"

	cases := []struct {
		desc   string
		body   map[string]interface{}
		isPKCE bool
	}{
		{
			desc: "Implict Flow Recovery",
			body: map[string]interface{}{
				"email": testEmail,
			},
			isPKCE: false,
		},
		{
			desc: "PKCE Flow",
			body: map[string]interface{}{
				"email": testEmail,
				// Code Challenge needs to be at least 43 characters long
				"code_challenge":        "6b151854-cc15-4e29-8db7-3d3a9f15b3066b151854-cc15-4e29-8db7-3d3a9f15b306",
				"code_challenge_method": models.SHA256.String(),
			},
			isPKCE: true,
		},
	}

	for _, c := range cases {
		ts.Run(c.desc, func() {
			// Reset user
			u.EmailConfirmedAt = nil
			require.NoError(ts.T(), ts.API.db.Update(u))
			// Request body
			var buffer bytes.Buffer
			require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(c.body))

			// Setup request
			req := httptest.NewRequest(http.MethodPost, "http://localhost/recover", &buffer)
			req.Header.Set("Content-Type", "application/json")

			// Setup response recorder
			w := httptest.NewRecorder()
			ts.API.handler.ServeHTTP(w, req)
			assert.Equal(ts.T(), http.StatusOK, w.Code)

			u, err = models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
			require.NoError(ts.T(), err)

			assert.WithinDuration(ts.T(), time.Now(), *u.RecoverySentAt, 1*time.Second)
			assert.False(ts.T(), u.IsConfirmed())

			reqURL := fmt.Sprintf("http://localhost/verify?type=%s&token=%s", recoveryVerification, u.RecoveryToken)
			req = httptest.NewRequest(http.MethodGet, reqURL, nil)

			w = httptest.NewRecorder()
			ts.API.handler.ServeHTTP(w, req)
			assert.Equal(ts.T(), http.StatusSeeOther, w.Code)

			u, err = models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
			require.NoError(ts.T(), err)
			assert.True(ts.T(), u.IsConfirmed())

			if c.isPKCE {
				rURL, _ := w.Result().Location()

				f, err := url.ParseQuery(rURL.RawQuery)
				require.NoError(ts.T(), err)
				assert.NotEmpty(ts.T(), f.Get("code"))
			}
		})
	}
}

func (ts *VerifyTestSuite) TestVerifySecureEmailChange() {
	currentEmail := "test@example.com"
	newEmail := "new@example.com"

	// Change from new email to current email and back to new email
	cases := []struct {
		desc         string
		body         map[string]interface{}
		isPKCE       bool
		currentEmail string
		newEmail     string
	}{
		{
			desc: "Implict Flow Email Change",
			body: map[string]interface{}{
				"email": newEmail,
			},
			isPKCE:       false,
			currentEmail: currentEmail,
			newEmail:     newEmail,
		},
		{
			desc: "PKCE Email Change",
			body: map[string]interface{}{
				"email": currentEmail,
				// Code Challenge needs to be at least 43 characters long
				"code_challenge":        "6b151854-cc15-4e29-8db7-3d3a9f15b3066b151854-cc15-4e29-8db7-3d3a9f15b306",
				"code_challenge_method": models.SHA256.String(),
			},
			isPKCE:       true,
			currentEmail: newEmail,
			newEmail:     currentEmail,
		},
	}

	for _, c := range cases {
		u, err := models.FindUserByEmailAndAudience(ts.API.db, c.currentEmail, ts.Config.JWT.Aud)
		require.NoError(ts.T(), err)

		u.EmailChangeSentAt = &time.Time{}
		require.NoError(ts.T(), ts.API.db.Update(u))

		// Request body
		var buffer bytes.Buffer
		require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(c.body))

		// Setup request
		req := httptest.NewRequest(http.MethodPut, "http://localhost/user", &buffer)
		req.Header.Set("Content-Type", "application/json")

		// Generate access token for request
		var token string
		token, err = generateAccessToken(ts.API.db, u, nil, &ts.Config.JWT)
		require.NoError(ts.T(), err)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

		// Setup response recorder
		w := httptest.NewRecorder()
		ts.API.handler.ServeHTTP(w, req)
		assert.Equal(ts.T(), http.StatusOK, w.Code)

		u, err = models.FindUserByEmailAndAudience(ts.API.db, c.currentEmail, ts.Config.JWT.Aud)
		require.NoError(ts.T(), err)

		assert.WithinDuration(ts.T(), time.Now(), *u.EmailChangeSentAt, 1*time.Second)
		assert.False(ts.T(), u.IsConfirmed())

		// Verify new email
		reqURL := fmt.Sprintf("http://localhost/verify?type=%s&token=%s", emailChangeVerification, u.EmailChangeTokenNew)
		req = httptest.NewRequest(http.MethodGet, reqURL, nil)

		w = httptest.NewRecorder()
		ts.API.handler.ServeHTTP(w, req)

		require.Equal(ts.T(), http.StatusSeeOther, w.Code)
		urlVal, err := url.Parse(w.Result().Header.Get("Location"))
		ts.Require().NoError(err, "redirect url parse failed")
		v, err := url.ParseQuery(urlVal.Fragment)
		ts.Require().NoError(err)
		ts.Require().NotEmpty(v.Get("message"))

		u, err = models.FindUserByEmailAndAudience(ts.API.db, c.currentEmail, ts.Config.JWT.Aud)
		require.NoError(ts.T(), err)
		assert.Equal(ts.T(), singleConfirmation, u.EmailChangeConfirmStatus)

		// Verify old email
		reqURL = fmt.Sprintf("http://localhost/verify?type=%s&token=%s", emailChangeVerification, u.EmailChangeTokenCurrent)
		req = httptest.NewRequest(http.MethodGet, reqURL, nil)

		w = httptest.NewRecorder()
		ts.API.handler.ServeHTTP(w, req)
		require.Equal(ts.T(), http.StatusSeeOther, w.Code)

		urlVal, err = url.Parse(w.Header().Get("Location"))
		ts.Require().NoError(err, "redirect url parse failed")
		if !c.isPKCE {
			v, err = url.ParseQuery(urlVal.Fragment)
			ts.Require().NoError(err)
			ts.Require().NotEmpty(v.Get("access_token"))
			ts.Require().NotEmpty(v.Get("expires_in"))
			ts.Require().NotEmpty(v.Get("refresh_token"))
		} else if c.isPKCE {
			v, err = url.ParseQuery(urlVal.RawQuery)
			ts.Require().NoError(err)
			ts.Require().NotEmpty(v.Get("code"))
		}

		// user's email should've been updated to newEmail
		u, err = models.FindUserByEmailAndAudience(ts.API.db, c.newEmail, ts.Config.JWT.Aud)
		require.NoError(ts.T(), err)
		require.Equal(ts.T(), zeroConfirmation, u.EmailChangeConfirmStatus)

		// Reset confirmation status after each test
		u.EmailConfirmedAt = nil
		require.NoError(ts.T(), ts.API.db.Update(u))

	}
}

func (ts *VerifyTestSuite) TestExpiredConfirmationToken() {
	u, err := models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	u.ConfirmationToken = "asdf3"
	sentTime := time.Now().Add(-48 * time.Hour)
	u.ConfirmationSentAt = &sentTime
	require.NoError(ts.T(), ts.API.db.Update(u))

	// Setup request
	reqURL := fmt.Sprintf("http://localhost/verify?type=%s&token=%s", signupVerification, u.ConfirmationToken)
	req := httptest.NewRequest(http.MethodGet, reqURL, nil)

	// Setup response recorder
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	assert.Equal(ts.T(), http.StatusSeeOther, w.Code)

	rurl, err := url.Parse(w.Header().Get("Location"))
	require.NoError(ts.T(), err, "redirect url parse failed")

	f, err := url.ParseQuery(rurl.Fragment)
	require.NoError(ts.T(), err)
	assert.Equal(ts.T(), "401", f.Get("error_code"))
	assert.Equal(ts.T(), "Email link is invalid or has expired", f.Get("error_description"))
	assert.Equal(ts.T(), "unauthorized_client", f.Get("error"))
}

func (ts *VerifyTestSuite) TestInvalidOtp() {
	u, err := models.FindUserByPhoneAndAudience(ts.API.db, "12345678", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	sentTime := time.Now().Add(-48 * time.Hour)
	u.ConfirmationToken = "123456"
	u.ConfirmationSentAt = &sentTime
	u.PhoneChange = "22222222"
	u.PhoneChangeToken = "123456"
	u.PhoneChangeSentAt = &sentTime
	require.NoError(ts.T(), ts.API.db.Update(u))

	type ResponseBody struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
	}

	expectedResponse := ResponseBody{
		Code: http.StatusUnauthorized,
		Msg:  "Token has expired or is invalid",
	}

	cases := []struct {
		desc     string
		sentTime time.Time
		body     map[string]interface{}
		expected ResponseBody
	}{
		{
			desc:     "Expired Sms OTP",
			sentTime: time.Now().Add(-48 * time.Hour),
			body: map[string]interface{}{
				"type":  smsVerification,
				"token": u.ConfirmationToken,
				"phone": u.GetPhone(),
			},
			expected: expectedResponse,
		},
		{
			desc:     "Invalid Sms OTP",
			sentTime: time.Now(),
			body: map[string]interface{}{
				"type":  smsVerification,
				"token": "invalid_otp",
				"phone": u.GetPhone(),
			},
			expected: expectedResponse,
		},
		{
			desc:     "Invalid Phone Change OTP",
			sentTime: time.Now(),
			body: map[string]interface{}{
				"type":  phoneChangeVerification,
				"token": "invalid_otp",
				"phone": u.PhoneChange,
			},
			expected: expectedResponse,
		},
		{
			desc:     "Invalid Email OTP",
			sentTime: time.Now(),
			body: map[string]interface{}{
				"type":  signupVerification,
				"token": "invalid_otp",
				"email": u.GetEmail(),
			},
			expected: expectedResponse,
		},
	}

	for _, c := range cases {
		ts.Run(c.desc, func() {
			// update token sent time
			sentTime = time.Now()
			u.ConfirmationSentAt = &c.sentTime
			require.NoError(ts.T(), ts.API.db.Update(u))

			var buffer bytes.Buffer
			require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(c.body))

			// Setup request
			req := httptest.NewRequest(http.MethodPost, "http://localhost/verify", &buffer)
			req.Header.Set("Content-Type", "application/json")

			// Setup response recorder
			w := httptest.NewRecorder()
			ts.API.handler.ServeHTTP(w, req)

			b, err := io.ReadAll(w.Body)
			require.NoError(ts.T(), err)
			var resp ResponseBody
			err = json.Unmarshal(b, &resp)
			require.NoError(ts.T(), err)
			assert.Equal(ts.T(), c.expected.Code, resp.Code)
			assert.Equal(ts.T(), c.expected.Msg, resp.Msg)

		})
	}
}

func (ts *VerifyTestSuite) TestExpiredRecoveryToken() {
	u, err := models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	u.RecoveryToken = "asdf3"
	sentTime := time.Now().Add(-48 * time.Hour)
	u.RecoverySentAt = &sentTime
	require.NoError(ts.T(), ts.API.db.Update(u))

	// Setup request
	reqURL := fmt.Sprintf("http://localhost/verify?type=%s&token=%s", "signup", u.RecoveryToken)
	req := httptest.NewRequest(http.MethodGet, reqURL, nil)

	// Setup response recorder
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)

	assert.Equal(ts.T(), http.StatusSeeOther, w.Code, w.Body.String())
}

func (ts *VerifyTestSuite) TestVerifyPermitedCustomUri() {
	u, err := models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	u.RecoverySentAt = &time.Time{}
	require.NoError(ts.T(), ts.API.db.Update(u))

	// Request body
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"email": "test@example.com",
	}))

	// Setup request
	req := httptest.NewRequest(http.MethodPost, "http://localhost/recover", &buffer)
	req.Header.Set("Content-Type", "application/json")

	// Setup response recorder
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	assert.Equal(ts.T(), http.StatusOK, w.Code)

	u, err = models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)

	assert.WithinDuration(ts.T(), time.Now(), *u.RecoverySentAt, 1*time.Second)
	assert.False(ts.T(), u.IsConfirmed())

	redirectURL, _ := url.Parse(ts.Config.URIAllowList[0])

	reqURL := fmt.Sprintf("http://localhost/verify?type=%s&token=%s&redirect_to=%s", "recovery", u.RecoveryToken, redirectURL.String())
	req = httptest.NewRequest(http.MethodGet, reqURL, nil)

	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	assert.Equal(ts.T(), http.StatusSeeOther, w.Code)
	rURL, _ := w.Result().Location()
	assert.Equal(ts.T(), redirectURL.Hostname(), rURL.Hostname())

	u, err = models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	assert.True(ts.T(), u.IsConfirmed())
}

func (ts *VerifyTestSuite) TestVerifyNotPermitedCustomUri() {
	u, err := models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	u.RecoverySentAt = &time.Time{}
	require.NoError(ts.T(), ts.API.db.Update(u))

	// Request body
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"email": "test@example.com",
	}))

	// Setup request
	req := httptest.NewRequest(http.MethodPost, "http://localhost/recover", &buffer)
	req.Header.Set("Content-Type", "application/json")

	// Setup response recorder
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	assert.Equal(ts.T(), http.StatusOK, w.Code)

	u, err = models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)

	assert.WithinDuration(ts.T(), time.Now(), *u.RecoverySentAt, 1*time.Second)
	assert.False(ts.T(), u.IsConfirmed())

	fakeredirectURL, _ := url.Parse("http://custom-url.com")
	siteURL, _ := url.Parse(ts.Config.SiteURL)

	reqURL := fmt.Sprintf("http://localhost/verify?type=%s&token=%s&redirect_to=%s", "recovery", u.RecoveryToken, fakeredirectURL.String())
	req = httptest.NewRequest(http.MethodGet, reqURL, nil)

	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	assert.Equal(ts.T(), http.StatusSeeOther, w.Code)
	rURL, _ := w.Result().Location()
	assert.Equal(ts.T(), siteURL.Hostname(), rURL.Hostname())

	u, err = models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	assert.True(ts.T(), u.IsConfirmed())
}

func (ts *VerifyTestSuite) TestVerifySignupWithredirectURLContainedPath() {
	testCases := []struct {
		desc                string
		siteURL             string
		uriAllowList        []string
		requestredirectURL  string
		expectedredirectURL string
	}{
		{
			desc:                "same site url and redirect url with path",
			siteURL:             "http://localhost:3000/#/",
			uriAllowList:        []string{"http://localhost:3000"},
			requestredirectURL:  "http://localhost:3000/#/",
			expectedredirectURL: "http://localhost:3000/#/",
		},
		{
			desc:                "different site url and redirect url in allow list",
			siteURL:             "https://someapp-something.codemagic.app/#/",
			uriAllowList:        []string{"http://localhost:3000"},
			requestredirectURL:  "http://localhost:3000",
			expectedredirectURL: "http://localhost:3000",
		},
		{
			desc:                "different site url and redirect url not in allow list",
			siteURL:             "https://someapp-something.codemagic.app/#/",
			uriAllowList:        []string{"http://localhost:3000"},
			requestredirectURL:  "http://localhost:3000/docs",
			expectedredirectURL: "https://someapp-something.codemagic.app/#/",
		},
		{
			desc:                "same wildcard site url and redirect url in allow list",
			siteURL:             "http://sub.test.dev:3000/#/",
			uriAllowList:        []string{"http://*.test.dev:3000"},
			requestredirectURL:  "http://sub.test.dev:3000/#/",
			expectedredirectURL: "http://sub.test.dev:3000/#/",
		},
		{
			desc:                "different wildcard site url and redirect url in allow list",
			siteURL:             "http://sub.test.dev/#/",
			uriAllowList:        []string{"http://*.other.dev:3000"},
			requestredirectURL:  "http://sub.other.dev:3000",
			expectedredirectURL: "http://sub.other.dev:3000",
		},
		{
			desc:                "different wildcard site url and redirect url not in allow list",
			siteURL:             "http://test.dev:3000/#/",
			uriAllowList:        []string{"http://*.allowed.dev:3000"},
			requestredirectURL:  "http://sub.test.dev:3000/#/",
			expectedredirectURL: "http://test.dev:3000/#/",
		},
		{
			desc:                "exact mobile deep link redirect url in allow list",
			siteURL:             "http://test.dev:3000/#/",
			uriAllowList:        []string{"twitter://timeline"},
			requestredirectURL:  "twitter://timeline",
			expectedredirectURL: "twitter://timeline",
		},
		// previously the below example was not allowed and with good
		// reason, however users do want flexibility in the redirect
		// URL after the scheme, which is why the example is now corrected
		{
			desc:                "wildcard mobile deep link redirect url in allow list",
			siteURL:             "http://test.dev:3000/#/",
			uriAllowList:        []string{"com.example.app://**"},
			requestredirectURL:  "com.example.app://sign-in/v2",
			expectedredirectURL: "com.example.app://sign-in/v2",
		},
		{
			desc:                "redirect respects . separator",
			siteURL:             "http://localhost:3000",
			uriAllowList:        []string{"http://*.*.dev:3000"},
			requestredirectURL:  "http://foo.bar.dev:3000",
			expectedredirectURL: "http://foo.bar.dev:3000",
		},
		{
			desc:                "redirect does not respect . separator",
			siteURL:             "http://localhost:3000",
			uriAllowList:        []string{"http://*.dev:3000"},
			requestredirectURL:  "http://foo.bar.dev:3000",
			expectedredirectURL: "http://localhost:3000",
		},
		{
			desc:                "redirect respects / separator in url subdirectory",
			siteURL:             "http://localhost:3000",
			uriAllowList:        []string{"http://test.dev:3000/*/*"},
			requestredirectURL:  "http://test.dev:3000/bar/foo",
			expectedredirectURL: "http://test.dev:3000/bar/foo",
		},
		{
			desc:                "redirect does not respect / separator in url subdirectory",
			siteURL:             "http://localhost:3000",
			uriAllowList:        []string{"http://test.dev:3000/*"},
			requestredirectURL:  "http://test.dev:3000/bar/foo",
			expectedredirectURL: "http://localhost:3000",
		},
	}

	for _, tC := range testCases {
		ts.Run(tC.desc, func() {
			// prepare test data
			ts.Config.SiteURL = tC.siteURL
			redirectURL := tC.requestredirectURL
			ts.Config.URIAllowList = tC.uriAllowList
			ts.Config.ApplyDefaults()

			// set verify token to user as it actual do in magic link method
			u, err := models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
			require.NoError(ts.T(), err)
			u.ConfirmationToken = "someToken"
			sendTime := time.Now().Add(time.Hour)
			u.ConfirmationSentAt = &sendTime
			require.NoError(ts.T(), ts.API.db.Update(u))

			reqURL := fmt.Sprintf("http://localhost/verify?type=%s&token=%s&redirect_to=%s", "signup", u.ConfirmationToken, redirectURL)
			req := httptest.NewRequest(http.MethodGet, reqURL, nil)

			w := httptest.NewRecorder()
			ts.API.handler.ServeHTTP(w, req)
			assert.Equal(ts.T(), http.StatusSeeOther, w.Code)
			rURL, _ := w.Result().Location()
			assert.Contains(ts.T(), rURL.String(), tC.expectedredirectURL) // redirected url starts with per test value

			u, err = models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
			require.NoError(ts.T(), err)
			assert.True(ts.T(), u.IsConfirmed())
		})
	}
}

func (ts *VerifyTestSuite) TestVerifyPKCEOTP() {

	u, err := models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	u.ConfirmationToken = "pkce_confirmation_token"
	u.RecoveryToken = "pkce_recovery_token"
	t := time.Now()
	u.ConfirmationSentAt = &t
	u.RecoverySentAt = &t
	u.EmailChangeSentAt = &t

	require.NoError(ts.T(), ts.API.db.Update(u))

	cases := []struct {
		desc                 string
		payload              *VerifyParams
		authenticationMethod models.AuthenticationMethod
	}{
		{
			desc: "Verify banned user on signup",
			payload: &VerifyParams{
				Type:  "signup",
				Token: u.ConfirmationToken,
			},
			authenticationMethod: models.EmailSignup,
		},
		{
			desc: "Verify magiclink",
			payload: &VerifyParams{
				Type:  "magiclink",
				Token: u.RecoveryToken,
			},
			authenticationMethod: models.MagicLink,
		},
	}
	for _, c := range cases {
		ts.Run(c.desc, func() {
			var buffer bytes.Buffer
			require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(c.payload))
			codeChallenge := "codechallengecodechallengcodechallengcodechallengcodechallenge" + c.payload.Type
			err := models.NewFlowStateWithUserID(ts.API.db, c.authenticationMethod.String(), codeChallenge, models.SHA256, c.authenticationMethod, &u.ID)
			require.NoError(ts.T(), err)

			requestUrl := fmt.Sprintf("http://localhost/verify?type=%v&token=%v", c.payload.Type, c.payload.Token)
			req := httptest.NewRequest(http.MethodGet, requestUrl, &buffer)
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			ts.API.handler.ServeHTTP(w, req)
			assert.Equal(ts.T(), http.StatusSeeOther, w.Code)
			rURL, _ := w.Result().Location()

			u, err = models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
			require.NoError(ts.T(), err)
			assert.True(ts.T(), u.IsConfirmed())

			f, err := url.ParseQuery(rURL.RawQuery)
			require.NoError(ts.T(), err)
			assert.NotEmpty(ts.T(), f.Get("code"))
		})
	}

}

func (ts *VerifyTestSuite) TestVerifyBannedUser() {
	u, err := models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	u.ConfirmationToken = "confirmation_token"
	u.RecoveryToken = "recovery_token"
	u.EmailChangeTokenCurrent = "current_email_change_token"
	u.EmailChangeTokenNew = "new_email_change_token"
	t := time.Now()
	u.ConfirmationSentAt = &t
	u.RecoverySentAt = &t
	u.EmailChangeSentAt = &t

	t = time.Now().Add(24 * time.Hour)
	u.BannedUntil = &t
	require.NoError(ts.T(), ts.API.db.Update(u))

	cases := []struct {
		desc    string
		payload *VerifyParams
	}{
		{
			desc: "Verify banned user on signup",
			payload: &VerifyParams{
				Type:  "signup",
				Token: u.ConfirmationToken,
			},
		},
		{
			desc: "Verify banned user on invite",
			payload: &VerifyParams{
				Type:  "invite",
				Token: u.ConfirmationToken,
			},
		},
		{
			desc: "Verify banned user on recover",
			payload: &VerifyParams{
				Type:  "recovery",
				Token: u.RecoveryToken,
			},
		},
		{
			desc: "Verify banned user on magiclink",
			payload: &VerifyParams{
				Type:  "magiclink",
				Token: u.RecoveryToken,
			},
		},
		{
			desc: "Verify banned user on email change",
			payload: &VerifyParams{
				Type:  "email_change",
				Token: u.EmailChangeTokenCurrent,
			},
		},
	}

	for _, c := range cases {
		ts.Run(c.desc, func() {
			var buffer bytes.Buffer
			require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(c.payload))

			requestUrl := fmt.Sprintf("http://localhost/verify?type=%v&token=%v", c.payload.Type, c.payload.Token)
			req := httptest.NewRequest(http.MethodGet, requestUrl, &buffer)
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			ts.API.handler.ServeHTTP(w, req)
			assert.Equal(ts.T(), http.StatusSeeOther, w.Code)

			rurl, err := url.Parse(w.Header().Get("Location"))
			require.NoError(ts.T(), err, "redirect url parse failed")

			f, err := url.ParseQuery(rurl.Fragment)
			require.NoError(ts.T(), err)
			assert.Equal(ts.T(), "401", f.Get("error_code"))
		})
	}
}

func (ts *VerifyTestSuite) TestVerifyValidOtp() {
	u, err := models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	u.EmailChange = "new@example.com"
	u.Phone = "12345678"
	u.PhoneChange = "1234567890"
	require.NoError(ts.T(), ts.API.db.Update(u))

	type expected struct {
		code int
	}

	expectedResponse := expected{
		code: http.StatusOK,
	}

	cases := []struct {
		desc     string
		sentTime time.Time
		body     map[string]interface{}
		expected
	}{
		{
			desc:     "Valid SMS OTP",
			sentTime: time.Now(),
			body: map[string]interface{}{
				"type":      smsVerification,
				"tokenHash": fmt.Sprintf("%x", sha256.Sum224([]byte(u.GetPhone()+"123456"))),
				"token":     "123456",
				"phone":     u.GetPhone(),
			},
			expected: expectedResponse,
		},
		{
			desc:     "Valid Confirmation OTP",
			sentTime: time.Now(),
			body: map[string]interface{}{
				"type":      signupVerification,
				"tokenHash": fmt.Sprintf("%x", sha256.Sum224([]byte(u.GetEmail()+"123456"))),
				"token":     "123456",
				"email":     u.GetEmail(),
			},
			expected: expectedResponse,
		},
		{
			desc:     "Valid Recovery OTP",
			sentTime: time.Now(),
			body: map[string]interface{}{
				"type":      recoveryVerification,
				"tokenHash": fmt.Sprintf("%x", sha256.Sum224([]byte(u.GetEmail()+"123456"))),
				"token":     "123456",
				"email":     u.GetEmail(),
			},
			expected: expectedResponse,
		},
		{
			desc:     "Valid Email OTP",
			sentTime: time.Now(),
			body: map[string]interface{}{
				"type":      emailOTPVerification,
				"tokenHash": fmt.Sprintf("%x", sha256.Sum224([]byte(u.GetEmail()+"123456"))),
				"token":     "123456",
				"email":     u.GetEmail(),
			},
			expected: expectedResponse,
		},
		{
			desc:     "Valid Email Change OTP",
			sentTime: time.Now(),
			body: map[string]interface{}{
				"type":      emailChangeVerification,
				"tokenHash": fmt.Sprintf("%x", sha256.Sum224([]byte(u.EmailChange+"123456"))),
				"token":     "123456",
				"email":     u.EmailChange,
			},
			expected: expectedResponse,
		},
		{
			desc:     "Valid Phone Change OTP",
			sentTime: time.Now(),
			body: map[string]interface{}{
				"type":      phoneChangeVerification,
				"tokenHash": fmt.Sprintf("%x", sha256.Sum224([]byte(u.PhoneChange+"123456"))),
				"token":     "123456",
				"phone":     u.PhoneChange,
			},
			expected: expectedResponse,
		},
	}

	for _, c := range cases {
		ts.Run(c.desc, func() {
			// create user
			u.ConfirmationSentAt = &c.sentTime
			u.RecoverySentAt = &c.sentTime
			u.EmailChangeSentAt = &c.sentTime
			u.PhoneChangeSentAt = &c.sentTime
			u.ConfirmationToken = c.body["tokenHash"].(string)
			u.RecoveryToken = c.body["tokenHash"].(string)
			u.EmailChangeTokenNew = c.body["tokenHash"].(string)
			u.PhoneChangeToken = c.body["tokenHash"].(string)
			require.NoError(ts.T(), ts.API.db.Update(u))

			var buffer bytes.Buffer
			require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(c.body))

			// Setup request
			req := httptest.NewRequest(http.MethodPost, "http://localhost/verify", &buffer)
			req.Header.Set("Content-Type", "application/json")

			// Setup response recorder
			w := httptest.NewRecorder()
			ts.API.handler.ServeHTTP(w, req)
			assert.Equal(ts.T(), c.expected.code, w.Code)
		})
	}
}
