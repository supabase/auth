package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/conf"
	mail "github.com/supabase/auth/internal/mailer"
	"github.com/supabase/auth/internal/models"
)

type OtpTestSuite struct {
	suite.Suite
	API    *API
	Config *conf.GlobalConfiguration
}

func TestOtp(t *testing.T) {
	api, config, err := setupAPIForTest()
	require.NoError(t, err)

	ts := &OtpTestSuite{
		API:    api,
		Config: config,
	}
	defer api.db.Close()

	suite.Run(t, ts)
}

func (ts *OtpTestSuite) SetupTest() {
	models.TruncateAll(ts.API.db)

}

func (ts *OtpTestSuite) TestOtpPKCE() {
	ts.Config.External.Phone.Enabled = true
	testCodeChallenge := "testtesttesttesttesttesttestteststeststesttesttesttest"

	var buffer bytes.Buffer
	cases := []struct {
		desc     string
		params   OtpParams
		expected struct {
			code     int
			response map[string]interface{}
		}
	}{
		{
			desc: "Test (PKCE) Success Magiclink Otp",
			params: OtpParams{
				Email:               "test@example.com",
				CreateUser:          true,
				CodeChallengeMethod: "s256",
				CodeChallenge:       testCodeChallenge,
			},
			expected: struct {
				code     int
				response map[string]interface{}
			}{
				http.StatusOK,
				make(map[string]interface{}),
			},
		},
		{
			desc: "Test (PKCE) Failure, no code challenge",
			params: OtpParams{
				Email:               "test@example.com",
				CreateUser:          true,
				CodeChallengeMethod: "s256",
			},
			expected: struct {
				code     int
				response map[string]interface{}
			}{
				http.StatusBadRequest,
				map[string]interface{}{
					"code":       float64(http.StatusBadRequest),
					"error_code": apierrors.ErrorCodeValidationFailed,
					"msg":        "PKCE flow requires code_challenge_method and code_challenge",
				},
			},
		},
		{
			desc: "Test (PKCE) Failure, no code challenge method",
			params: OtpParams{
				Email:         "test@example.com",
				CreateUser:    true,
				CodeChallenge: testCodeChallenge,
			},
			expected: struct {
				code     int
				response map[string]interface{}
			}{
				http.StatusBadRequest,
				map[string]interface{}{
					"code":       float64(http.StatusBadRequest),
					"error_code": apierrors.ErrorCodeValidationFailed,
					"msg":        "PKCE flow requires code_challenge_method and code_challenge",
				},
			},
		},
		{
			desc: "Test (PKCE) Success, phone with valid params",
			params: OtpParams{
				Phone:               "123456789",
				CreateUser:          true,
				CodeChallengeMethod: "s256",
				CodeChallenge:       testCodeChallenge,
			},
			expected: struct {
				code     int
				response map[string]interface{}
			}{
				http.StatusInternalServerError,
				map[string]interface{}{
					"code": float64(http.StatusInternalServerError),
					"msg":  "Unable to get SMS provider",
				},
			},
		},
	}
	for _, c := range cases {
		ts.Run(c.desc, func() {
			require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(c.params))

			req := httptest.NewRequest(http.MethodPost, "/otp", &buffer)
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			ts.API.handler.ServeHTTP(w, req)

			require.Equal(ts.T(), c.expected.code, w.Code)
			data := make(map[string]interface{})
			require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))

		})
	}
}

func (ts *OtpTestSuite) TestOtp() {
	// Configured to allow testing of invalid channel params
	ts.Config.External.Phone.Enabled = true
	cases := []struct {
		desc     string
		params   OtpParams
		expected struct {
			code     int
			response map[string]interface{}
		}
	}{
		{
			desc: "Test Success Magiclink Otp",
			params: OtpParams{
				Email:      "test@example.com",
				CreateUser: true,
				Data: map[string]interface{}{
					"somedata": "metadata",
				},
			},
			expected: struct {
				code     int
				response map[string]interface{}
			}{
				http.StatusOK,
				make(map[string]interface{}),
			},
		},
		{
			desc: "Test Failure Pass Both Email & Phone",
			params: OtpParams{
				Email:      "test@example.com",
				Phone:      "123456789",
				CreateUser: true,
			},
			expected: struct {
				code     int
				response map[string]interface{}
			}{
				http.StatusBadRequest,
				map[string]interface{}{
					"code":       float64(http.StatusBadRequest),
					"error_code": apierrors.ErrorCodeValidationFailed,
					"msg":        "Only an email address or phone number should be provided",
				},
			},
		},
		{
			desc: "Test Failure invalid channel param",
			params: OtpParams{
				Phone:      "123456789",
				Channel:    "invalidchannel",
				CreateUser: true,
			},
			expected: struct {
				code     int
				response map[string]interface{}
			}{
				http.StatusBadRequest,
				map[string]interface{}{
					"code":       float64(http.StatusBadRequest),
					"error_code": apierrors.ErrorCodeValidationFailed,
					"msg":        InvalidChannelError,
				},
			},
		},
	}

	for _, c := range cases {
		ts.Run(c.desc, func() {
			var buffer bytes.Buffer
			require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(c.params))

			req := httptest.NewRequest(http.MethodPost, "/otp", &buffer)
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()

			ts.API.handler.ServeHTTP(w, req)

			require.Equal(ts.T(), c.expected.code, w.Code)

			data := make(map[string]interface{})
			require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))

			// response should be empty
			assert.Equal(ts.T(), data, c.expected.response)
		})
	}
}

func (ts *OtpTestSuite) TestNoSignupsForOtp() {
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"email":       "newuser@example.com",
		"create_user": false,
	}))

	req := httptest.NewRequest(http.MethodPost, "/otp", &buffer)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)

	require.Equal(ts.T(), http.StatusUnprocessableEntity, w.Code)

	data := make(map[string]interface{})
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))

	// response should be empty
	assert.Equal(ts.T(), data, map[string]interface{}{
		"code":       float64(http.StatusUnprocessableEntity),
		"error_code": apierrors.ErrorCodeOTPDisabled,
		"msg":        "Signups not allowed for otp",
	})
}

func (ts *OtpTestSuite) TestSubsequentOtp() {
	ts.Config.SMTP.MaxFrequency = 0
	userEmail := "foo@example.com"
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"email": userEmail,
	}))

	req := httptest.NewRequest(http.MethodPost, "/otp", &buffer)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)

	require.Equal(ts.T(), http.StatusOK, w.Code)

	newUser, err := models.FindUserByEmailAndAudience(ts.API.db, userEmail, ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), newUser.ConfirmationToken)
	require.NotEmpty(ts.T(), newUser.ConfirmationSentAt)
	require.Empty(ts.T(), newUser.RecoveryToken)
	require.Empty(ts.T(), newUser.RecoverySentAt)
	require.Empty(ts.T(), newUser.EmailConfirmedAt)

	// since the signup process hasn't been completed,
	// subsequent requests for another magiclink should not create a recovery token
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"email": userEmail,
	}))

	req = httptest.NewRequest(http.MethodPost, "/otp", &buffer)
	req.Header.Set("Content-Type", "application/json")

	w = httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)

	require.Equal(ts.T(), http.StatusOK, w.Code)

	user, err := models.FindUserByEmailAndAudience(ts.API.db, userEmail, ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), user.ConfirmationToken)
	require.NotEmpty(ts.T(), user.ConfirmationSentAt)
	require.Empty(ts.T(), user.RecoveryToken)
	require.Empty(ts.T(), user.RecoverySentAt)
	require.Empty(ts.T(), user.EmailConfirmedAt)
}

// requirePasswordRejected asserts that password no longer authenticates the
// user. Signup now stores the magic link's temporary password on unconfirmed
// users, so the invariant is that the attacker's password is gone, not that
// the user has no password at all.
func (ts *OtpTestSuite) requirePasswordRejected(user *models.User, password string) {
	ok, _, err := user.Authenticate(context.Background(), ts.API.db, password, ts.Config.Security.DBEncryption.DecryptionKeys, false, "")
	require.NoError(ts.T(), err)
	require.False(ts.T(), ok)
}

func (ts *OtpTestSuite) TestOtpClearsUnconfirmedPassword() {
	ts.Config.SMTP.MaxFrequency = 0
	ts.Config.Mailer.Autoconfirm = false
	defer func() { ts.Config.Mailer.Autoconfirm = false }()

	userEmail := "victim@example.com"
	attackerPassword := "attacker-password-123"

	// attacker signs up with the victim's email and leaves it unconfirmed
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"email":    userEmail,
		"password": attackerPassword,
	}))
	req := httptest.NewRequest(http.MethodPost, "/signup", &buffer)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	user, err := models.FindUserByEmailAndAudience(ts.API.db, userEmail, ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	require.False(ts.T(), user.IsConfirmed())
	require.True(ts.T(), user.HasPassword())

	// email owner requests a magic link
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"email": userEmail,
	}))
	req = httptest.NewRequest(http.MethodPost, "/otp", &buffer)
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	user, err = models.FindUserByEmailAndAudience(ts.API.db, userEmail, ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	ts.requirePasswordRejected(user, attackerPassword)
	require.NotEmpty(ts.T(), user.ConfirmationToken)

	// email owner confirms through the link
	reqURL := fmt.Sprintf("http://localhost/verify?type=%s&token=%s", mail.SignupVerification, user.ConfirmationToken)
	req = httptest.NewRequest(http.MethodGet, reqURL, nil)
	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusSeeOther, w.Code)

	user, err = models.FindUserByEmailAndAudience(ts.API.db, userEmail, ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	require.True(ts.T(), user.IsConfirmed())
	ts.requirePasswordRejected(user, attackerPassword)

	// attacker can no longer sign in with their password
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"email":    userEmail,
		"password": attackerPassword,
	}))
	req = httptest.NewRequest(http.MethodPost, "/token?grant_type=password", &buffer)
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusBadRequest, w.Code)
}

func (ts *OtpTestSuite) TestOtpClearsUnconfirmedPasswordWithAutoconfirm() {
	ts.Config.SMTP.MaxFrequency = 0
	ts.Config.Mailer.Autoconfirm = true
	defer func() { ts.Config.Mailer.Autoconfirm = false }()

	userEmail := "victim@example.com"

	// unconfirmed user created before autoconfirm was enabled
	u, err := models.NewUser("", userEmail, "attacker-password-123", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(u))
	require.True(ts.T(), u.HasPassword())

	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"email": userEmail,
	}))
	req := httptest.NewRequest(http.MethodPost, "/otp", &buffer)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	user, err := models.FindUserByEmailAndAudience(ts.API.db, userEmail, ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	require.True(ts.T(), user.IsConfirmed())
	ts.requirePasswordRejected(user, "attacker-password-123")
}

func (ts *OtpTestSuite) TestOtpKeepsConfirmedPassword() {
	ts.Config.SMTP.MaxFrequency = 0

	userEmail := "confirmed@example.com"
	u, err := models.NewUser("", userEmail, "password-123", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err)
	now := time.Now()
	u.EmailConfirmedAt = &now
	require.NoError(ts.T(), ts.API.db.Create(u))

	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"email": userEmail,
	}))
	req := httptest.NewRequest(http.MethodPost, "/otp", &buffer)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	user, err := models.FindUserByEmailAndAudience(ts.API.db, userEmail, ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	require.True(ts.T(), user.HasPassword())
}

func (ts *OtpTestSuite) TestOtpBannedUser() {
	ts.Config.SMTP.MaxFrequency = 0
	ts.Config.Sms.MaxFrequency = 0
	ts.Config.External.Phone.Enabled = true
	ts.Config.Sms.TestOTP = map[string]string{"123456789": "000000"}
	defer func() {
		ts.Config.Sms.TestOTP = nil
	}()

	u, err := models.NewUser("123456789", "banned@example.com", "password", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(u))
	require.NoError(ts.T(), u.Confirm(ts.API.db))
	require.NoError(ts.T(), u.ConfirmPhone(ts.API.db))
	require.NoError(ts.T(), u.Ban(ts.API.db, time.Hour))

	cases := []struct {
		desc string
		path string
		body map[string]interface{}
	}{
		{
			desc: "Magic link via /otp",
			path: "/otp",
			body: map[string]interface{}{"email": u.GetEmail()},
		},
		{
			desc: "Magic link via /magiclink",
			path: "/magiclink",
			body: map[string]interface{}{"email": u.GetEmail()},
		},
		{
			desc: "SMS OTP via /otp",
			path: "/otp",
			body: map[string]interface{}{"phone": u.GetPhone()},
		},
	}

	for _, c := range cases {
		ts.Run(c.desc, func() {
			var buffer bytes.Buffer
			require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(c.body))
			req := httptest.NewRequest(http.MethodPost, c.path, &buffer)
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			ts.API.handler.ServeHTTP(w, req)
			require.Equal(ts.T(), http.StatusOK, w.Code)
			require.JSONEq(ts.T(), "{}", w.Body.String())

			dbUser, err := models.FindUserByID(ts.API.db, u.ID)
			require.NoError(ts.T(), err)
			require.Empty(ts.T(), dbUser.RecoveryToken)
			require.Nil(ts.T(), dbUser.RecoverySentAt)
			require.Empty(ts.T(), dbUser.ConfirmationToken)
			require.Nil(ts.T(), dbUser.ConfirmationSentAt)
		})
	}

	ts.Run("Expired ban sends magic link again", func() {
		pastBan := time.Now().Add(-time.Hour)
		u.BannedUntil = &pastBan
		require.NoError(ts.T(), ts.API.db.UpdateOnly(u, "banned_until"))

		var buffer bytes.Buffer
		require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{"email": u.GetEmail()}))
		req := httptest.NewRequest(http.MethodPost, "/otp", &buffer)
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		ts.API.handler.ServeHTTP(w, req)
		require.Equal(ts.T(), http.StatusOK, w.Code)

		dbUser, err := models.FindUserByID(ts.API.db, u.ID)
		require.NoError(ts.T(), err)
		require.NotEmpty(ts.T(), dbUser.RecoveryToken)
		require.NotNil(ts.T(), dbUser.RecoverySentAt)
	})
}

func (ts *OtpTestSuite) TestOtpBannedUserMaxFrequency() {
	origSMTP, origSms := ts.Config.SMTP.MaxFrequency, ts.Config.Sms.MaxFrequency
	ts.Config.SMTP.MaxFrequency = time.Minute
	ts.Config.Sms.MaxFrequency = time.Minute
	ts.Config.External.Phone.Enabled = true
	defer func() {
		ts.Config.SMTP.MaxFrequency = origSMTP
		ts.Config.Sms.MaxFrequency = origSms
	}()

	sentAt := time.Now().Add(-10 * time.Second)
	u, err := models.NewUser("987654321", "banned-freq@example.com", "password", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err)
	u.RecoverySentAt = &sentAt
	u.ConfirmationSentAt = &sentAt
	require.NoError(ts.T(), ts.API.db.Create(u))
	require.NoError(ts.T(), u.Confirm(ts.API.db))
	require.NoError(ts.T(), u.ConfirmPhone(ts.API.db))
	require.NoError(ts.T(), u.Ban(ts.API.db, time.Hour))

	for _, c := range []struct {
		path string
		body map[string]interface{}
	}{
		{"/otp", map[string]interface{}{"email": u.GetEmail()}},
		{"/magiclink", map[string]interface{}{"email": u.GetEmail()}},
		{"/otp", map[string]interface{}{"phone": u.GetPhone()}},
	} {
		var buffer bytes.Buffer
		require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(c.body))
		req := httptest.NewRequest(http.MethodPost, c.path, &buffer)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		ts.API.handler.ServeHTTP(w, req)
		require.Equal(ts.T(), http.StatusTooManyRequests, w.Code, c.path)
	}
}
