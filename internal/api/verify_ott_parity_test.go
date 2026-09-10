package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"

	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/crypto"
	mail "github.com/supabase/auth/internal/mailer"
	"github.com/supabase/auth/internal/models"
)

// The typed-OTP verification path can read the challenge from either the legacy
// users.*_token columns or, with EnableOTTAsSourceOfTruth, from the one_time_tokens table.
//
// These tests run every flow once per store with identical seeding and ensure the outcome is equal.
const (
	parityOTP       = "123456"
	parityEmail     = "test@example.com"
	parityPhone     = "12345678"
	parityNewEmail  = "new@example.com"
	parityNewPhone  = "1234567890"
	parityForbidden = "Token has expired or is invalid"
)

// otpParityOutcome is everything a client or an operator can observe after a
// POST /verify: the HTTP result, the user state it left, and the audit action it recorded.
type otpParityOutcome struct {
	Status         int
	ErrorCode      string
	Msg            string
	Action         string
	EmailConfirmed bool
	PhoneConfirmed bool
	Email          string
	Phone          string
}

type otpParityCase struct {
	// seed receives a user freshly created by the test suite's SetupTest fn, creates an OTT challenge
	// and modifies the user to include the relevant OTT values, given our dual-write approach today.
	seed        func(u *models.User)
	requestBody map[string]interface{}
	// configure applies per-case config, and runs once per store. It returns a restore function that will be called after the test.
	configure func() func()
	expected  otpParityOutcome
}

func (ts *VerifyTestSuite) TestVerifyOTPParityEmailFlows() {
	now := time.Now()
	expired := now.Add(-48 * time.Hour)
	emailHash := crypto.GenerateTokenHash(parityEmail, parityOTP)

	forbidden := otpParityOutcome{
		Status:    http.StatusForbidden,
		ErrorCode: apierrors.ErrorCodeOTPExpired,
		Msg:       parityForbidden,
		Email:     parityEmail,
		Phone:     parityPhone,
	}

	signedUp := otpParityOutcome{
		Status:         http.StatusOK,
		Action:         string(models.UserSignedUpAction),
		EmailConfirmed: true,
		Email:          parityEmail,
		Phone:          parityPhone,
	}

	loggedIn := otpParityOutcome{
		Status:         http.StatusOK,
		Action:         string(models.LoginAction),
		EmailConfirmed: true,
		Email:          parityEmail,
		Phone:          parityPhone,
	}

	cases := map[string]otpParityCase{
		"signup with a valid code confirms the user": {
			seed: func(u *models.User) {
				ts.seedChallenge(u, models.ConfirmationToken, parityEmail, emailHash, now, time.Hour)
			},
			requestBody: emailOTPBody(mail.SignupVerification, parityEmail),
			expected:    signedUp,
		},
		"signup with an expired code is rejected": {
			seed: func(u *models.User) {
				ts.seedChallenge(u, models.ConfirmationToken, parityEmail, emailHash, expired, -time.Hour)
			},
			requestBody: emailOTPBody(mail.SignupVerification, parityEmail),
			expected:    forbidden,
		},
		"signup with the wrong code is rejected": {
			seed: func(u *models.User) {
				ts.seedChallenge(u, models.ConfirmationToken, parityEmail, crypto.GenerateTokenHash(parityEmail, "999999"), now, time.Hour)
			},
			requestBody: emailOTPBody(mail.SignupVerification, parityEmail),
			expected:    forbidden,
		},
		"invite with a valid code confirms the user": {
			seed: func(u *models.User) {
				u.InvitedAt = &now
				ts.seedChallenge(u, models.ConfirmationToken, parityEmail, emailHash, now, time.Hour)
			},
			requestBody: emailOTPBody(mail.InviteVerification, parityEmail),
			expected:    signedUp,
		},
		"magiclink with a valid code signs a confirmed user in": {
			seed: func(u *models.User) {
				u.EmailConfirmedAt = &now
				ts.seedChallenge(u, models.RecoveryToken, parityEmail, emailHash, now, time.Hour)
			},
			requestBody: emailOTPBody(mail.MagicLinkVerification, parityEmail),
			expected:    loggedIn,
		},
		"magiclink with a pkce_ prefixed stored hash accepts the plain code": {
			seed: func(u *models.User) {
				u.EmailConfirmedAt = &now
				ts.seedChallenge(u, models.RecoveryToken, parityEmail, PKCEPrefix+emailHash, now, time.Hour)
			},
			requestBody: emailOTPBody(mail.MagicLinkVerification, parityEmail),
			expected:    loggedIn,
		},
		"recovery with a valid code signs a confirmed user in": {
			seed: func(u *models.User) {
				u.EmailConfirmedAt = &now
				ts.seedChallenge(u, models.RecoveryToken, parityEmail, emailHash, now, time.Hour)
			},
			requestBody: emailOTPBody(mail.RecoveryVerification, parityEmail),
			expected:    loggedIn,
		},
		"email type with a confirmation token runs the signup flow": {
			seed: func(u *models.User) {
				ts.seedChallenge(u, models.ConfirmationToken, parityEmail, emailHash, now, time.Hour)
			},
			requestBody: emailOTPBody(mail.EmailOTPVerification, parityEmail),
			expected:    signedUp,
		},
		"email type with a recovery token runs the magiclink flow": {
			seed: func(u *models.User) {
				u.EmailConfirmedAt = &now
				ts.seedChallenge(u, models.RecoveryToken, parityEmail, emailHash, now, time.Hour)
			},
			requestBody: emailOTPBody(mail.EmailOTPVerification, parityEmail),
			expected:    loggedIn,
		},
		"email type with no matching challenge is rejected": {
			requestBody: emailOTPBody(mail.EmailOTPVerification, parityEmail),
			expected:    forbidden,
		},
		"email change with a valid code moves the user to the new address": {
			// Secure email change defaults to on, which needs a OTP for the old email address too. Turn it off and then revert.
			configure: func() func() {
				previous := ts.Config.Mailer.SecureEmailChangeEnabled
				ts.Config.Mailer.SecureEmailChangeEnabled = false
				return func() { ts.Config.Mailer.SecureEmailChangeEnabled = previous }
			},
			seed: func(u *models.User) {
				u.EmailChange = parityNewEmail
				ts.seedChallenge(u, models.EmailChangeTokenNew, parityNewEmail, crypto.GenerateTokenHash(parityNewEmail, parityOTP), now, time.Hour)
			},
			requestBody: emailOTPBody(mail.EmailChangeVerification, parityNewEmail),
			expected: otpParityOutcome{
				Status:         http.StatusOK,
				Action:         string(models.UserModifiedAction),
				EmailConfirmed: true,
				Email:          parityNewEmail,
				Phone:          parityPhone,
			},
		},
		"a banned user is rejected": {
			seed: func(u *models.User) {
				bannedUntil := now.Add(time.Hour)
				u.BannedUntil = &bannedUntil
				ts.seedChallenge(u, models.ConfirmationToken, parityEmail, emailHash, now, time.Hour)
			},
			requestBody: emailOTPBody(mail.SignupVerification, parityEmail),
			expected: otpParityOutcome{
				Status:    http.StatusForbidden,
				ErrorCode: apierrors.ErrorCodeUserBanned,
				Msg:       "User is banned",
				Email:     parityEmail,
				Phone:     parityPhone,
			},
		},
		"an unknown verification type is rejected": {
			seed: func(u *models.User) {
				ts.seedChallenge(u, models.ConfirmationToken, parityEmail, emailHash, now, time.Hour)
			},
			requestBody: emailOTPBody("bogus", parityEmail),
			expected:    forbidden,
		},
	}

	ts.runOTPParityCases(cases)
}

func (ts *VerifyTestSuite) TestVerifyOTPParityPhoneFlows() {
	now := time.Now()
	expired := now.Add(-48 * time.Hour)
	phoneHash := crypto.GenerateTokenHash(parityPhone, parityOTP)

	forbidden := otpParityOutcome{
		Status:    http.StatusForbidden,
		ErrorCode: apierrors.ErrorCodeOTPExpired,
		Msg:       parityForbidden,
		Email:     parityEmail,
		Phone:     parityPhone,
	}

	phoneSignedUp := otpParityOutcome{
		Status:         http.StatusOK,
		Action:         string(models.UserSignedUpAction),
		PhoneConfirmed: true,
		Email:          parityEmail,
		Phone:          parityPhone,
	}

	phoneChanged := otpParityOutcome{
		Status:         http.StatusOK,
		Action:         string(models.UserModifiedAction),
		PhoneConfirmed: true,
		Email:          parityEmail,
		Phone:          parityNewPhone,
	}

	cases := map[string]otpParityCase{
		"sms with a valid code confirms the phone": {
			seed: func(u *models.User) {
				ts.seedChallenge(u, models.ConfirmationToken, parityPhone, phoneHash, now, time.Hour)
			},
			requestBody: phoneOTPBody(smsVerification, parityPhone),
			expected:    phoneSignedUp,
		},
		"sms with an expired code is rejected": {
			seed: func(u *models.User) {
				ts.seedChallenge(u, models.ConfirmationToken, parityPhone, phoneHash, expired, -time.Hour)
			},
			requestBody: phoneOTPBody(smsVerification, parityPhone),
			expected:    forbidden,
		},
		"sms with the wrong code is rejected": {
			seed: func(u *models.User) {
				ts.seedChallenge(u, models.ConfirmationToken, parityPhone, crypto.GenerateTokenHash(parityPhone, "999999"), now, time.Hour)
			},
			requestBody: phoneOTPBody(smsVerification, parityPhone),
			expected:    forbidden,
		},
		"phone change with a valid code moves the user to the new number": {
			seed: func(u *models.User) {
				u.PhoneChange = parityNewPhone
				ts.seedChallenge(u, models.PhoneChangeToken, parityNewPhone, crypto.GenerateTokenHash(parityNewPhone, parityOTP), now, time.Hour)
			},
			requestBody: phoneOTPBody(phoneChangeVerification, parityNewPhone),
			expected:    phoneChanged,
		},
	}

	ts.runOTPParityCases(cases)
}

// runOTPParityCases runs each case against both stores and asserts that both
// produce the expected outcome and agree with each other.
func (ts *VerifyTestSuite) runOTPParityCases(testCases map[string]otpParityCase) {
	originalFlag := ts.Config.Experimental.EnableOTTAsSourceOfTruth
	defer func() { ts.Config.Experimental.EnableOTTAsSourceOfTruth = originalFlag }()

	for name, tc := range testCases {
		ts.Run(name, func() {
			var legacyOutcome, ottOutcome otpParityOutcome

			ts.Run("legacy users columns", func() {
				legacyOutcome = ts.runOTPParityCase(tc, false)
			})
			ts.Run("one_time_tokens", func() {
				ottOutcome = ts.runOTPParityCase(tc, true)
			})

			require.Equal(ts.T(), legacyOutcome, ottOutcome,
				"legacy and one_time_tokens paths must produce the same outcome")
		})
	}
}

// runOTPParityCase runs one case against one store and returns the outcome it
// observed. enableOTT selects the store. It also asserts the outcome matches
// c.expected, so a failure names the store that diverged.
func (ts *VerifyTestSuite) runOTPParityCase(c otpParityCase, enableOTT bool) otpParityOutcome {
	ts.SetupTest()
	ts.Config.Experimental.EnableOTTAsSourceOfTruth = enableOTT
	if c.configure != nil {
		restore := c.configure()
		defer restore()
	}

	u, err := models.FindUserByEmailAndAudience(ts.API.db, parityEmail, ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	if c.seed != nil {
		c.seed(u)
	}

	since := time.Now()
	w := ts.postVerify(c.requestBody)
	outcome := ts.observeOutcome(w, u.ID, since)
	require.Equal(ts.T(), c.expected, outcome)
	return outcome
}

// saveUser persists every pending change on u. Call it from a seed that
// changes u but stores no challenge. seedChallenge calls it already.
func (ts *VerifyTestSuite) saveUser(u *models.User) {
	require.NoError(ts.T(), ts.API.db.Update(u))
}

// seedChallenge stores hash in the users column and the one_time_tokens row
// for tokenType, mirroring what the send paths write. relatesTo is the address
// or number the code was sent to. It persists u, so it also saves any other
// change the case made.
func (ts *VerifyTestSuite) seedChallenge(u *models.User, tokenType models.OneTimeTokenType, relatesTo, hash string, sentAt time.Time, validity time.Duration) {
	switch tokenType {
	case models.ConfirmationToken:
		u.ConfirmationToken = hash
		u.ConfirmationSentAt = &sentAt
	case models.RecoveryToken:
		u.RecoveryToken = hash
		u.RecoverySentAt = &sentAt
	case models.EmailChangeTokenNew:
		u.EmailChangeTokenNew = hash
		u.EmailChangeSentAt = &sentAt
	case models.PhoneChangeToken:
		u.PhoneChangeToken = hash
		u.PhoneChangeSentAt = &sentAt
	default:
		ts.T().Fatalf("seedChallenge does not support token type %s", tokenType)
	}

	ts.saveUser(u)
	require.NoError(ts.T(), models.CreateOneTimeToken(ts.API.db, u.ID, relatesTo, hash, tokenType, validity))
}

func (ts *VerifyTestSuite) postVerify(body map[string]interface{}) *httptest.ResponseRecorder {
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(body))

	req := httptest.NewRequest(http.MethodPost, "http://localhost/verify", &buffer)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	return w
}

func (ts *VerifyTestSuite) observeOutcome(w *httptest.ResponseRecorder, userID uuid.UUID, since time.Time) otpParityOutcome {
	outcome := otpParityOutcome{Status: w.Code}

	if w.Code != http.StatusOK {
		var body struct {
			ErrorCode string `json:"error_code"`
			Msg       string `json:"msg"`
		}
		require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&body))
		outcome.ErrorCode = body.ErrorCode
		outcome.Msg = body.Msg
	}

	u, err := models.FindUserByID(ts.API.db, userID)
	require.NoError(ts.T(), err)
	outcome.EmailConfirmed = u.EmailConfirmedAt != nil
	outcome.PhoneConfirmed = u.PhoneConfirmedAt != nil
	outcome.Email = u.GetEmail()
	outcome.Phone = u.GetPhone()

	logs, err := models.FindAuditLogEntries(ts.API.db, nil, "", nil)
	require.NoError(ts.T(), err)
	if len(logs) > 0 && !logs[0].CreatedAt.Before(since) {
		outcome.Action, _ = logs[0].Payload["action"].(string)
	}

	return outcome
}

func emailOTPBody(verifyType, email string) map[string]interface{} {
	return map[string]interface{}{
		"type":  verifyType,
		"token": parityOTP,
		"email": email,
	}
}

func phoneOTPBody(verifyType, phone string) map[string]interface{} {
	return map[string]interface{}{
		"type":  verifyType,
		"token": parityOTP,
		"phone": phone,
	}
}

// TestVerifyOTPParityIdentifierBinding covers the guarantee that the
// identifier in the request is the one the challenge was issued for.
//
// The legacy path gets this from its identifier-keyed user lookups: the email or phone in the
// body is the lookup key, so a mismatch is a not-found. The one_time_tokens path finds the user
// by token hash, so it has to check the binding itself.
func (ts *VerifyTestSuite) TestVerifyOTPParityIdentifierBinding() {
	now := time.Now()
	emailHash := crypto.GenerateTokenHash(parityEmail, parityOTP)
	phoneHash := crypto.GenerateTokenHash(parityPhone, parityOTP)

	forbidden := otpParityOutcome{
		Status:    http.StatusForbidden,
		ErrorCode: apierrors.ErrorCodeOTPExpired,
		Msg:       parityForbidden,
		Email:     parityEmail,
		Phone:     parityPhone,
	}

	testCases := map[string]otpParityCase{
		"a phone code posted as signup does not confirm the email": {
			seed: func(u *models.User) {
				ts.seedChallenge(u, models.ConfirmationToken, parityPhone, phoneHash, now, time.Hour)
			},
			requestBody: phoneOTPBody(mail.SignupVerification, parityPhone),
			expected:    forbidden,
		},
		"a phone code posted as the generic email type does not confirm the email": {
			seed: func(u *models.User) {
				ts.seedChallenge(u, models.ConfirmationToken, parityPhone, phoneHash, now, time.Hour)
			},
			requestBody: phoneOTPBody(mail.EmailOTPVerification, parityPhone),
			expected:    forbidden,
		},
		"an email code posted as sms does not confirm the phone": {
			seed: func(u *models.User) {
				ts.seedChallenge(u, models.ConfirmationToken, parityEmail, emailHash, now, time.Hour)
			},
			requestBody: emailOTPBody(smsVerification, parityEmail),
			expected:    forbidden,
		},
		"an SSO user cannot verify a typed OTP": {
			seed: func(u *models.User) {
				u.IsSSOUser = true
				ts.seedChallenge(u, models.ConfirmationToken, parityEmail, emailHash, now, time.Hour)
			},
			requestBody: emailOTPBody(mail.SignupVerification, parityEmail),
			expected:    forbidden,
		},
	}

	ts.runOTPParityCases(testCases)
}
