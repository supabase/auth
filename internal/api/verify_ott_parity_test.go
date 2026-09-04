package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"gopkg.in/h2non/gock.v1"

	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/api/sms_provider"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/crypto"
	mail "github.com/supabase/auth/internal/mailer"
	"github.com/supabase/auth/internal/models"
)

// The typed-OTP verify path can read the challenge from either the legacy
// users.*_token columns or, with EnableOTTAsSourceOfTruth, from the
// one_time_tokens table. These tests run every flow once per store and require
// the observable outcome to be identical. Both stores are seeded the way the
// send paths seed them, so a failure here is a divergence in verify logic, not
// in the fixtures.

const (
	parityOTP        = "123456"
	parityEmail      = "test@example.com"
	parityPhone      = "12345678"
	parityNewEmail   = "new@example.com"
	parityNewPhone   = "1234567890"
	parityForbidden  = "Token has expired or is invalid"
	twilioServiceSid = "VA-parity-test"
)

// otpParityOutcome is everything a client or an operator can observe after a
// POST /verify: the HTTP result, the user state it left, and the audit action
// it recorded.
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
	desc string
	// seed writes the challenge to both stores and returns the request body.
	// It receives a freshly created, unconfirmed user.
	seed func(u *models.User) map[string]interface{}
	// configure applies per-case config and returns a function that undoes
	// it. It runs once per store, so consumable mocks are re-armed each time.
	configure func() func()
	expected  otpParityOutcome
}

func (ts *VerifyTestSuite) TestVerifyOTPParityEmailFlows() {
	now := time.Now()
	expired := now.Add(-48 * time.Hour)
	emailHash := crypto.GenerateTokenHash(parityEmail, parityOTP)

	baseline := otpParityOutcome{Email: parityEmail, Phone: parityPhone}
	forbidden := baseline
	forbidden.Status = http.StatusForbidden
	forbidden.ErrorCode = apierrors.ErrorCodeOTPExpired
	forbidden.Msg = parityForbidden

	signedUp := baseline
	signedUp.Status = http.StatusOK
	signedUp.Action = string(models.UserSignedUpAction)
	signedUp.EmailConfirmed = true

	loggedIn := baseline
	loggedIn.Status = http.StatusOK
	loggedIn.Action = string(models.LoginAction)
	loggedIn.EmailConfirmed = true

	cases := []otpParityCase{
		{
			desc: "signup with a valid code confirms the user",
			seed: func(u *models.User) map[string]interface{} {
				ts.seedChallenge(u, models.ConfirmationToken, emailHash, now, time.Hour)
				return emailOTPBody(mail.SignupVerification, parityEmail)
			},
			expected: signedUp,
		},
		{
			desc: "signup with an expired code is rejected",
			seed: func(u *models.User) map[string]interface{} {
				ts.seedChallenge(u, models.ConfirmationToken, emailHash, expired, -time.Hour)
				return emailOTPBody(mail.SignupVerification, parityEmail)
			},
			expected: forbidden,
		},
		{
			desc: "signup with the wrong code is rejected",
			seed: func(u *models.User) map[string]interface{} {
				ts.seedChallenge(u, models.ConfirmationToken, crypto.GenerateTokenHash(parityEmail, "999999"), now, time.Hour)
				return emailOTPBody(mail.SignupVerification, parityEmail)
			},
			expected: forbidden,
		},
		{
			desc: "invite with a valid code confirms the user",
			seed: func(u *models.User) map[string]interface{} {
				u.InvitedAt = &now
				ts.seedChallenge(u, models.ConfirmationToken, emailHash, now, time.Hour)
				return emailOTPBody(mail.InviteVerification, parityEmail)
			},
			expected: signedUp,
		},
		{
			desc: "magiclink with a valid code signs a confirmed user in",
			seed: func(u *models.User) map[string]interface{} {
				u.EmailConfirmedAt = &now
				ts.seedChallenge(u, models.RecoveryToken, emailHash, now, time.Hour)
				return emailOTPBody(mail.MagicLinkVerification, parityEmail)
			},
			expected: loggedIn,
		},
		{
			desc: "recovery with a valid code signs a confirmed user in",
			seed: func(u *models.User) map[string]interface{} {
				u.EmailConfirmedAt = &now
				ts.seedChallenge(u, models.RecoveryToken, emailHash, now, time.Hour)
				return emailOTPBody(mail.RecoveryVerification, parityEmail)
			},
			expected: loggedIn,
		},
		{
			// Tokens issued through the PKCE flow are stored with a pkce_
			// prefix. A plain code must still match them.
			desc: "magiclink with a pkce_ prefixed stored hash accepts the plain code",
			seed: func(u *models.User) map[string]interface{} {
				u.EmailConfirmedAt = &now
				ts.seedChallenge(u, models.RecoveryToken, PKCEPrefix+emailHash, now, time.Hour)
				return emailOTPBody(mail.MagicLinkVerification, parityEmail)
			},
			expected: loggedIn,
		},
		{
			// The generic "email" type must resolve to the signup flow when the
			// stored challenge is a confirmation token.
			desc: "email type with a confirmation token runs the signup flow",
			seed: func(u *models.User) map[string]interface{} {
				ts.seedChallenge(u, models.ConfirmationToken, emailHash, now, time.Hour)
				return emailOTPBody(mail.EmailOTPVerification, parityEmail)
			},
			expected: signedUp,
		},
		{
			// The generic "email" type must resolve to the magiclink flow when
			// the stored challenge is a recovery token.
			desc: "email type with a recovery token runs the magiclink flow",
			seed: func(u *models.User) map[string]interface{} {
				u.EmailConfirmedAt = &now
				ts.seedChallenge(u, models.RecoveryToken, emailHash, now, time.Hour)
				return emailOTPBody(mail.EmailOTPVerification, parityEmail)
			},
			expected: loggedIn,
		},
		{
			desc: "email type with no matching challenge is rejected",
			seed: func(u *models.User) map[string]interface{} {
				return emailOTPBody(mail.EmailOTPVerification, parityEmail)
			},
			expected: forbidden,
		},
		{
			desc: "email change with a valid code moves the user to the new address",
			configure: func() func() {
				previous := ts.Config.Mailer.SecureEmailChangeEnabled
				ts.Config.Mailer.SecureEmailChangeEnabled = false
				return func() { ts.Config.Mailer.SecureEmailChangeEnabled = previous }
			},
			seed: func(u *models.User) map[string]interface{} {
				u.EmailChange = parityNewEmail
				ts.seedChallenge(u, models.EmailChangeTokenNew, crypto.GenerateTokenHash(parityNewEmail, parityOTP), now, time.Hour)
				return emailOTPBody(mail.EmailChangeVerification, parityNewEmail)
			},
			expected: otpParityOutcome{
				Status:         http.StatusOK,
				Action:         string(models.UserModifiedAction),
				EmailConfirmed: true,
				Email:          parityNewEmail,
				Phone:          parityPhone,
			},
		},
		{
			desc: "a banned user is rejected before the challenge is checked",
			seed: func(u *models.User) map[string]interface{} {
				bannedUntil := now.Add(time.Hour)
				u.BannedUntil = &bannedUntil
				ts.seedChallenge(u, models.ConfirmationToken, emailHash, now, time.Hour)
				return emailOTPBody(mail.SignupVerification, parityEmail)
			},
			expected: otpParityOutcome{
				Status:    http.StatusForbidden,
				ErrorCode: apierrors.ErrorCodeUserBanned,
				Msg:       "User is banned",
				Email:     parityEmail,
				Phone:     parityPhone,
			},
		},
		{
			desc: "an unknown verification type is rejected",
			seed: func(u *models.User) map[string]interface{} {
				ts.seedChallenge(u, models.ConfirmationToken, emailHash, now, time.Hour)
				return emailOTPBody("bogus", parityEmail)
			},
			expected: forbidden,
		},
	}

	ts.runOTPParityCases(cases)
}

func (ts *VerifyTestSuite) TestVerifyOTPParityPhoneFlows() {
	now := time.Now()
	expired := now.Add(-48 * time.Hour)
	phoneHash := crypto.GenerateTokenHash(parityPhone, parityOTP)

	baseline := otpParityOutcome{Email: parityEmail, Phone: parityPhone}
	forbidden := baseline
	forbidden.Status = http.StatusForbidden
	forbidden.ErrorCode = apierrors.ErrorCodeOTPExpired
	forbidden.Msg = parityForbidden

	phoneSignedUp := baseline
	phoneSignedUp.Status = http.StatusOK
	phoneSignedUp.Action = string(models.UserSignedUpAction)
	phoneSignedUp.PhoneConfirmed = true

	phoneChanged := otpParityOutcome{
		Status:         http.StatusOK,
		Action:         string(models.UserModifiedAction),
		PhoneConfirmed: true,
		Email:          parityEmail,
		Phone:          parityNewPhone,
	}

	cases := []otpParityCase{
		{
			desc: "sms with a valid code confirms the phone",
			seed: func(u *models.User) map[string]interface{} {
				ts.seedChallenge(u, models.ConfirmationToken, phoneHash, now, time.Hour)
				return phoneOTPBody(smsVerification, parityPhone)
			},
			expected: phoneSignedUp,
		},
		{
			desc: "sms with an expired code is rejected",
			seed: func(u *models.User) map[string]interface{} {
				ts.seedChallenge(u, models.ConfirmationToken, phoneHash, expired, -time.Hour)
				return phoneOTPBody(smsVerification, parityPhone)
			},
			expected: forbidden,
		},
		{
			desc: "sms with the wrong code is rejected",
			seed: func(u *models.User) map[string]interface{} {
				ts.seedChallenge(u, models.ConfirmationToken, crypto.GenerateTokenHash(parityPhone, "999999"), now, time.Hour)
				return phoneOTPBody(smsVerification, parityPhone)
			},
			expected: forbidden,
		},
		{
			desc: "phone change with a valid code moves the user to the new number",
			seed: func(u *models.User) map[string]interface{} {
				u.PhoneChange = parityNewPhone
				ts.seedChallenge(u, models.PhoneChangeToken, crypto.GenerateTokenHash(parityNewPhone, parityOTP), now, time.Hour)
				return phoneOTPBody(phoneChangeVerification, parityNewPhone)
			},
			expected: phoneChanged,
		},
		{
			// A test OTP is accepted without any stored challenge. This is the
			// path app store reviewers and CI rely on.
			desc: "sms with a test OTP succeeds with no stored challenge",
			configure: func() func() {
				return ts.configureTestOTP(parityPhone, parityOTP)
			},
			seed: func(u *models.User) map[string]interface{} {
				return phoneOTPBody(smsVerification, parityPhone)
			},
			expected: phoneSignedUp,
		},
		{
			desc: "sms with a wrong code falls through the test OTP check and is rejected",
			configure: func() func() {
				return ts.configureTestOTP(parityPhone, "000000")
			},
			seed: func(u *models.User) map[string]interface{} {
				return phoneOTPBody(smsVerification, parityPhone)
			},
			expected: forbidden,
		},
		{
			// Twilio Verify generates and delivers its own code, so the locally
			// stored hash never matches what the user types. Twilio's answer
			// is the only thing that counts.
			desc: "sms with Twilio Verify accepts a code Twilio approves",
			configure: func() func() {
				return ts.configureTwilioVerify(map[string]interface{}{"status": "approved", "valid": true})
			},
			seed: func(u *models.User) map[string]interface{} {
				ts.seedChallenge(u, models.ConfirmationToken, crypto.GenerateTokenHash(parityPhone, "999999"), now, time.Hour)
				return phoneOTPBody(smsVerification, parityPhone)
			},
			expected: phoneSignedUp,
		},
		{
			desc: "sms with Twilio Verify rejects a code Twilio does not approve",
			configure: func() func() {
				return ts.configureTwilioVerify(map[string]interface{}{"status": "pending", "valid": false})
			},
			seed: func(u *models.User) map[string]interface{} {
				ts.seedChallenge(u, models.ConfirmationToken, phoneHash, now, time.Hour)
				return phoneOTPBody(smsVerification, parityPhone)
			},
			expected: forbidden,
		},
	}

	ts.runOTPParityCases(cases)
}

// runOTPParityCases runs each case against both stores and asserts that both
// produce the expected outcome and agree with each other.
func (ts *VerifyTestSuite) runOTPParityCases(cases []otpParityCase) {
	originalFlag := ts.Config.Experimental.EnableOTTAsSourceOfTruth
	defer func() { ts.Config.Experimental.EnableOTTAsSourceOfTruth = originalFlag }()

	modes := []struct {
		name string
		flag bool
	}{
		{name: "legacy users columns", flag: false},
		{name: "one_time_tokens", flag: true},
	}

	for _, caseItem := range cases {
		c := caseItem
		ts.Run(c.desc, func() {
			outcomes := make(map[string]otpParityOutcome, len(modes))

			for _, mode := range modes {
				m := mode
				ts.Run(m.name, func() {
					ts.SetupTest()
					ts.Config.Experimental.EnableOTTAsSourceOfTruth = m.flag
					if c.configure != nil {
						restore := c.configure()
						defer restore()
					}

					u, err := models.FindUserByEmailAndAudience(ts.API.db, parityEmail, ts.Config.JWT.Aud)
					require.NoError(ts.T(), err)
					body := c.seed(u)

					since := time.Now()
					w := ts.postVerify(body)
					outcome := ts.observeOutcome(w, u.ID, since)
					require.Equal(ts.T(), c.expected, outcome)
					outcomes[m.name] = outcome
				})
			}

			require.Equal(ts.T(), outcomes[modes[0].name], outcomes[modes[1].name],
				"legacy and one_time_tokens paths must produce the same outcome")
		})
	}
}

// seedChallenge stores hash in the users column and the one_time_tokens row
// for tokenType, mirroring what the send paths write. Any other pending
// change on u is persisted at the same time.
func (ts *VerifyTestSuite) seedChallenge(u *models.User, tokenType models.OneTimeTokenType, hash string, sentAt time.Time, validity time.Duration) {
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

	require.NoError(ts.T(), ts.API.db.Update(u))
	require.NoError(ts.T(), models.CreateOneTimeToken(ts.API.db, u.ID, "relates_to not used", hash, tokenType, validity))
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

// observeOutcome collects the response and the resulting user state. Only
// audit entries written after since are considered, so earlier entries in the
// same test run cannot leak into the result.
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

func (ts *VerifyTestSuite) configureTestOTP(phone, otp string) func() {
	previous := ts.Config.Sms.TestOTP
	ts.Config.Sms.TestOTP = map[string]string{phone: otp}
	return func() { ts.Config.Sms.TestOTP = previous }
}

// configureTwilioVerify switches the SMS provider to Twilio Verify and arms a
// single mocked VerificationCheck response.
func (ts *VerifyTestSuite) configureTwilioVerify(response map[string]interface{}) func() {
	previousProvider := ts.Config.Sms.Provider
	previousTwilio := ts.Config.Sms.TwilioVerify
	previousMock := sms_provider.MockProvider

	ts.Config.Sms.Provider = "twilio_verify"
	ts.Config.Sms.TwilioVerify = conf.TwilioVerifyProviderConfiguration{
		AccountSid:        "AC-parity-test",
		AuthToken:         "parity-test-token",
		MessageServiceSid: twilioServiceSid,
	}
	// The mock provider would short-circuit GetSmsProvider and never reach
	// the Twilio Verify type assertion.
	sms_provider.MockProvider = nil

	gock.New("https://verify.twilio.com/v2/Services/" + twilioServiceSid + "/VerificationCheck").
		Post("").
		Reply(http.StatusOK).
		JSON(response)

	return func() {
		gock.OffAll()
		sms_provider.MockProvider = previousMock
		ts.Config.Sms.TwilioVerify = previousTwilio
		ts.Config.Sms.Provider = previousProvider
	}
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
