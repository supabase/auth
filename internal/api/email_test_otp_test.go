package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/crypto"
	"github.com/supabase/auth/internal/mailer/mockclient"
	"github.com/supabase/auth/internal/models"
)

const (
	testOTPEmail = "test@example.com"
	testOTPCode  = "123456"
)

type EmailTestOTPTestSuite struct {
	suite.Suite
	API    *API
	Config *conf.GlobalConfiguration
	Mailer *mockclient.MockMailer
}

func TestEmailTestOTP(t *testing.T) {
	mockMailer := &mockclient.MockMailer{}
	api, config, err := setupAPIForTest(WithMailer(mockMailer))
	require.NoError(t, err)

	ts := &EmailTestOTPTestSuite{
		API:    api,
		Config: config,
		Mailer: mockMailer,
	}
	defer api.db.Close()

	suite.Run(t, ts)
}

func (ts *EmailTestOTPTestSuite) SetupTest() {
	models.TruncateAll(ts.API.db)
	ts.Mailer.Reset()

	// allow repeated sends to the same user within a test
	ts.Config.SMTP.MaxFrequency = 0
	ts.Config.Mailer.Autoconfirm = false
	ts.Config.Mailer.TestOTP = nil
	ts.Config.Mailer.TestOTPValidUntil = conf.Time{}
	ts.Config.External.Email.AuthorizedAddresses = nil

	u, err := models.NewUser("", testOTPEmail, "password", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err, "Error creating test user model")
	require.NoError(ts.T(), ts.API.db.Create(u), "Error saving new test user")
}

func (ts *EmailTestOTPTestSuite) TearDownTest() {
	ts.Config.Mailer.TestOTP = nil
	ts.Config.Mailer.TestOTPValidUntil = conf.Time{}
	ts.Config.External.Email.AuthorizedAddresses = nil
}

func (ts *EmailTestOTPTestSuite) findUser() *models.User {
	u, err := models.FindUserByEmailAndAudience(ts.API.db, testOTPEmail, ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	return u
}

// doTestSendEmailOtp mirrors doTestSendPhoneConfirmation in phone_test.go: it
// calls the send functions directly and checks the persisted token state and
// whether a mail was handed to the mailer.
func (ts *EmailTestOTPTestSuite) doTestSendEmailOtp(useTestOTP bool, flowType models.FlowType) {
	if useTestOTP {
		ts.Config.Mailer.TestOTP = map[string]string{testOTPEmail: testOTPCode}
	} else {
		ts.Config.Mailer.TestOTP = nil
	}

	req, err := http.NewRequest(http.MethodPost, "http://localhost:9998/otp", nil)
	require.NoError(ts.T(), err)

	expectedHash := addFlowPrefixToToken(crypto.GenerateTokenHash(testOTPEmail, testOTPCode), flowType)

	ts.Run("magic link", func() {
		ts.Mailer.Reset()
		u := ts.findUser()

		require.NoError(ts.T(), ts.API.sendMagicLink(req, ts.API.db, u, flowType))

		u = ts.findUser()
		require.NotEmpty(ts.T(), u.RecoveryToken)
		require.NotNil(ts.T(), u.RecoverySentAt)

		if useTestOTP {
			require.Empty(ts.T(), ts.Mailer.MagicLinkMailCalls)
			require.Equal(ts.T(), expectedHash, u.RecoveryToken)
		} else {
			require.Len(ts.T(), ts.Mailer.MagicLinkMailCalls, 1)
			require.NotEqual(ts.T(), expectedHash, u.RecoveryToken)
		}

		_, err := models.FindOneTimeToken(ts.API.db, u.RecoveryToken, models.RecoveryToken)
		require.NoError(ts.T(), err)
	})

	ts.Run("signup confirmation", func() {
		ts.Mailer.Reset()
		u := ts.findUser()

		require.NoError(ts.T(), ts.API.sendConfirmation(req, ts.API.db, u, flowType))

		u = ts.findUser()
		require.NotEmpty(ts.T(), u.ConfirmationToken)
		require.NotNil(ts.T(), u.ConfirmationSentAt)

		if useTestOTP {
			require.Empty(ts.T(), ts.Mailer.ConfirmationMailCalls)
			require.Equal(ts.T(), expectedHash, u.ConfirmationToken)
		} else {
			require.Len(ts.T(), ts.Mailer.ConfirmationMailCalls, 1)
			require.NotEqual(ts.T(), expectedHash, u.ConfirmationToken)
		}

		_, err := models.FindOneTimeToken(ts.API.db, u.ConfirmationToken, models.ConfirmationToken)
		require.NoError(ts.T(), err)
	})
}

func (ts *EmailTestOTPTestSuite) TestSendEmailOtp() {
	ts.doTestSendEmailOtp(false, models.ImplicitFlow)
}

func (ts *EmailTestOTPTestSuite) TestSendEmailOtpWithTestOTP() {
	ts.doTestSendEmailOtp(true, models.ImplicitFlow)
}

func (ts *EmailTestOTPTestSuite) TestSendEmailOtpWithTestOTPPKCE() {
	ts.doTestSendEmailOtp(true, models.PKCEFlow)

	u := ts.findUser()
	require.True(ts.T(), strings.HasPrefix(u.RecoveryToken, "pkce_"))
	require.True(ts.T(), strings.HasPrefix(u.ConfirmationToken, "pkce_"))
}

func (ts *EmailTestOTPTestSuite) TestTestOTPEmailIsCaseInsensitive() {
	ts.Config.Mailer.TestOTP = map[string]string{testOTPEmail: testOTPCode}

	otp, isTestOTP := ts.API.generateEmailOtp("  Test@Example.COM ")
	require.True(ts.T(), isTestOTP)
	require.Equal(ts.T(), testOTPCode, otp)

	otp, isTestOTP = ts.API.generateEmailOtp("other@example.com")
	require.False(ts.T(), isTestOTP)
	require.Len(ts.T(), otp, ts.Config.Mailer.OtpLength)
}

func (ts *EmailTestOTPTestSuite) TestTestOTPStillRequiresAuthorizedAddress() {
	ts.Config.Mailer.TestOTP = map[string]string{testOTPEmail: testOTPCode}
	ts.Config.External.Email.AuthorizedAddresses = []string{"someone-else@example.com"}

	req, err := http.NewRequest(http.MethodPost, "http://localhost:9998/otp", nil)
	require.NoError(ts.T(), err)

	u := ts.findUser()
	err = ts.API.sendMagicLink(req, ts.API.db, u, models.ImplicitFlow)
	require.Error(ts.T(), err)

	herr, ok := err.(*apierrors.HTTPError)
	require.True(ts.T(), ok)
	require.Equal(ts.T(), string(apierrors.ErrorCodeEmailAddressNotAuthorized), herr.ErrorCode)
	require.Empty(ts.T(), ts.Mailer.MagicLinkMailCalls)
}

func (ts *EmailTestOTPTestSuite) post(path string, body map[string]interface{}) *httptest.ResponseRecorder {
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(body))

	req := httptest.NewRequest(http.MethodPost, path, &buffer)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	return w
}

func (ts *EmailTestOTPTestSuite) decode(w *httptest.ResponseRecorder) map[string]interface{} {
	data := make(map[string]interface{})
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))
	return data
}

// TestOtpAndVerifyWithTestOTP exercises the full HTTP flow from issue #901: a
// brand-new email requests an OTP, nothing is sent, and the configured code
// verifies into a session. It then repeats the flow for the now-confirmed user
// which goes through the magic link sender instead of signup confirmation.
func (ts *EmailTestOTPTestSuite) TestOtpAndVerifyWithTestOTP() {
	models.TruncateAll(ts.API.db)
	ts.Mailer.Reset()

	newEmail := "new-user@example.com"
	ts.Config.Mailer.TestOTP = map[string]string{newEmail: testOTPCode}

	// 1. brand-new user: MagicLink routes through Signup -> sendConfirmation
	w := ts.post("/otp", map[string]interface{}{
		"email":       newEmail,
		"create_user": true,
	})
	require.Equal(ts.T(), http.StatusOK, w.Code)
	require.Empty(ts.T(), ts.Mailer.ConfirmationMailCalls)
	require.Empty(ts.T(), ts.Mailer.MagicLinkMailCalls)

	u, err := models.FindUserByEmailAndAudience(ts.API.db, newEmail, ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	require.False(ts.T(), u.IsConfirmed())
	require.Equal(ts.T(), crypto.GenerateTokenHash(newEmail, testOTPCode), u.ConfirmationToken)

	// 2. wrong code is rejected
	w = ts.post("/verify", map[string]interface{}{
		"type":  "email",
		"email": newEmail,
		"token": "000000",
	})
	require.Equal(ts.T(), http.StatusForbidden, w.Code)
	require.Equal(ts.T(), string(apierrors.ErrorCodeOTPExpired), ts.decode(w)["error_code"])

	// 3. the configured code verifies and returns a session
	w = ts.post("/verify", map[string]interface{}{
		"type":  "email",
		"email": newEmail,
		"token": testOTPCode,
	})
	require.Equal(ts.T(), http.StatusOK, w.Code)
	require.NotEmpty(ts.T(), ts.decode(w)["access_token"])

	u, err = models.FindUserByEmailAndAudience(ts.API.db, newEmail, ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	require.True(ts.T(), u.IsConfirmed())

	// 4. confirmed user: MagicLink goes through sendMagicLink
	w = ts.post("/otp", map[string]interface{}{
		"email": newEmail,
	})
	require.Equal(ts.T(), http.StatusOK, w.Code)
	require.Empty(ts.T(), ts.Mailer.MagicLinkMailCalls)

	w = ts.post("/verify", map[string]interface{}{
		"type":  "magiclink",
		"email": newEmail,
		"token": testOTPCode,
	})
	require.Equal(ts.T(), http.StatusOK, w.Code)
	require.NotEmpty(ts.T(), ts.decode(w)["access_token"])

	// 5. an expired test OTP configuration falls back to a real OTP and sends mail
	ts.Config.Mailer.TestOTPValidUntil = conf.Time{Time: time.Now().Add(-time.Hour)}

	w = ts.post("/otp", map[string]interface{}{
		"email": newEmail,
	})
	require.Equal(ts.T(), http.StatusOK, w.Code)
	require.Len(ts.T(), ts.Mailer.MagicLinkMailCalls, 1)

	w = ts.post("/verify", map[string]interface{}{
		"type":  "magiclink",
		"email": newEmail,
		"token": testOTPCode,
	})
	require.Equal(ts.T(), http.StatusForbidden, w.Code)
}
