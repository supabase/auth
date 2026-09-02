package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/crypto"
	"github.com/supabase/auth/internal/mailer"
	"github.com/supabase/auth/internal/mailer/mockclient"
	"github.com/supabase/auth/internal/models"
)

type RecoveryCodesTestSuite struct {
	suite.Suite
	API         *API
	Config      *conf.GlobalConfiguration
	Mailer      mailer.Mailer
	TestEmail   string
	TestUser    *models.User
	TestFactor  *models.Factor
	TestSession *models.Session
}

func TestRecoveryCodes(t *testing.T) {
	mockMailer := &mockclient.MockMailer{}
	api, config, err := setupAPIForTest(WithMailer(mockMailer))
	require.NoError(t, err)
	ts := &RecoveryCodesTestSuite{
		API:    api,
		Config: config,
		Mailer: mockMailer,
	}
	defer api.db.Close()
	suite.Run(t, ts)
}

func (ts *RecoveryCodesTestSuite) SetupTest() {
	models.TruncateAll(ts.API.db)

	ts.TestEmail = "test@example.com"
	u, err := models.NewUser("123456789", ts.TestEmail, "password", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err, "Error creating test user model")
	require.NoError(ts.T(), ts.API.db.Create(u), "Error saving new test user")

	// A verified TOTP factor so recovery codes are never the sole factor.
	f := models.NewTOTPFactor(u, "test_factor")
	require.NoError(ts.T(), f.SetSecret("secretkey", ts.Config.Security.DBEncryption.Encrypt, ts.Config.Security.DBEncryption.EncryptionKeyID, ts.Config.Security.DBEncryption.EncryptionKey))
	require.NoError(ts.T(), ts.API.db.Create(f), "Error saving new test factor")
	require.NoError(ts.T(), f.UpdateStatus(ts.API.db, models.FactorStateVerified))

	s, err := models.NewSession(u.ID, &f.ID)
	require.NoError(ts.T(), err, "Error creating test session")
	require.NoError(ts.T(), ts.API.db.Create(s), "Error saving test session")

	u, err = models.FindUserByEmailAndAudience(ts.API.db, ts.TestEmail, ts.Config.JWT.Aud)
	ts.Require().NoError(err)

	ts.TestUser = u
	ts.TestFactor = f
	ts.TestSession = s

	// ts.Config is shared across tests; reset every knob this suite touches.
	ts.Config.MFA.RecoveryCodes.EnrollEnabled = true
	ts.Config.MFA.RecoveryCodes.VerifyEnabled = true
	ts.Config.MFA.RecoveryCodes.MaxVerifyAttempts = 5
	ts.Config.MFA.RecoveryCodes.LockoutDuration = 15 * time.Minute
	ts.Config.MFA.MaxEnrolledFactors = 10
	ts.Config.MFA.MaxVerifiedFactors = 10
	ts.Config.Hook.MFAVerificationAttempt.Enabled = false
	ts.Config.Mailer.Notifications.MFAFactorEnrolledEnabled = false
	if mockMailer, ok := ts.Mailer.(*mockclient.MockMailer); ok {
		mockMailer.Reset()
	}
}

func (ts *RecoveryCodesTestSuite) token(user *models.User, sessionID *uuid.UUID) string {
	req := httptest.NewRequest(http.MethodPost, "/factors/recovery-codes", nil)
	token, _, err := ts.API.generateAccessToken(req, ts.API.db, user, sessionID, models.TOTPSignIn)
	require.NoError(ts.T(), err, "Error generating access token")
	return token
}

// aal2Token upgrades the test session to AAL2 and mints a token for it.
func (ts *RecoveryCodesTestSuite) aal2Token() string {
	require.NoError(ts.T(), ts.TestSession.UpdateAALAndAssociatedFactor(ts.API.db, models.AAL2, &ts.TestFactor.ID))
	return ts.token(ts.TestUser, &ts.TestSession.ID)
}

func (ts *RecoveryCodesTestSuite) serveRequest(method, path, token string, body io.Reader) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, body)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")
	ts.API.handler.ServeHTTP(w, req)
	return w
}

func (ts *RecoveryCodesTestSuite) requireErrorCode(w *httptest.ResponseRecorder, expectedStatus int, expectedErrorCode apierrors.ErrorCode) {
	require.Equal(ts.T(), expectedStatus, w.Code)
	var data HTTPError
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))
	require.Equal(ts.T(), expectedErrorCode, data.ErrorCode)
}

func (ts *RecoveryCodesTestSuite) performGenerate(token string, body io.Reader) RecoveryCodesResponse {
	w := ts.serveRequest(http.MethodPost, "http://localhost/factors/recovery-codes", token, body)
	require.Equal(ts.T(), http.StatusOK, w.Code)
	resp := RecoveryCodesResponse{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&resp))
	return resp
}

func (ts *RecoveryCodesTestSuite) TestRecoveryCodesStatusNotEnrolled() {
	token := ts.token(ts.TestUser, &ts.TestSession.ID)
	w := ts.serveRequest(http.MethodGet, "http://localhost/factors/recovery-codes", token, nil)
	ts.requireErrorCode(w, http.StatusNotFound, apierrors.ErrorCodeMFAFactorNotFound)
}

func (ts *RecoveryCodesTestSuite) TestRecoveryCodesStatusEnrolled() {
	token := ts.aal2Token()
	generateResp := ts.performGenerate(token, nil)

	w := ts.serveRequest(http.MethodGet, "http://localhost/factors/recovery-codes", token, nil)
	require.Equal(ts.T(), http.StatusOK, w.Code)
	statusResp := RecoveryCodesResponse{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&statusResp))
	require.Equal(ts.T(), generateResp.ID, statusResp.ID)
	require.Equal(ts.T(), models.RecoveryCode, statusResp.Type)
	require.Equal(ts.T(), 10, statusResp.Total)
	require.NotNil(ts.T(), statusResp.Remaining)
	require.Equal(ts.T(), 10, *statusResp.Remaining)
	require.Empty(ts.T(), statusResp.Codes)
	require.Empty(ts.T(), statusResp.FriendlyName)

	// Consume one code directly via models (verify endpoint is a later task).
	set, err := models.FindRecoveryCodeSetByUser(ts.API.db, ts.TestUser.ID)
	require.NoError(ts.T(), err)
	entries, err := models.FindUnusedRecoveryCodes(ts.API.db, set.ID)
	require.NoError(ts.T(), err)
	require.Len(ts.T(), entries, 10)
	require.NoError(ts.T(), entries[0].MarkConsumed(ts.API.db))

	w = ts.serveRequest(http.MethodGet, "http://localhost/factors/recovery-codes", token, nil)
	require.Equal(ts.T(), http.StatusOK, w.Code)
	statusResp = RecoveryCodesResponse{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&statusResp))
	require.Equal(ts.T(), 10, statusResp.Total)
	require.Equal(ts.T(), 9, *statusResp.Remaining)

	// Consume the rest: "remaining": 0 must still be serialized while codes
	// and friendly_name stay absent.
	for i := 1; i < len(entries); i++ {
		require.NoError(ts.T(), entries[i].MarkConsumed(ts.API.db))
	}
	w = ts.serveRequest(http.MethodGet, "http://localhost/factors/recovery-codes", token, nil)
	require.Equal(ts.T(), http.StatusOK, w.Code)
	rawResp := map[string]any{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&rawResp))
	remaining, ok := rawResp["remaining"]
	require.True(ts.T(), ok, "remaining should be present even when zero")
	require.EqualValues(ts.T(), 0, remaining)
	require.NotContains(ts.T(), rawResp, "codes")
	require.NotContains(ts.T(), rawResp, "friendly_name")
}

func (ts *RecoveryCodesTestSuite) TestRecoveryCodesGenerate() {
	token := ts.aal2Token()

	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]any{"friendly_name": "My recovery codes"}))
	resp := ts.performGenerate(token, &buffer)

	require.Equal(ts.T(), models.RecoveryCode, resp.Type)
	require.Equal(ts.T(), "My recovery codes", resp.FriendlyName)
	require.Equal(ts.T(), 10, resp.Total)
	require.Nil(ts.T(), resp.Remaining)
	require.Len(ts.T(), resp.Codes, 10)

	// Codes are returned in canonical normalized form; display formatting is a client concern.
	codeFormat := regexp.MustCompile("^[a-z2-7]{16}$")
	seen := make(map[string]bool)
	for _, code := range resp.Codes {
		require.Regexp(ts.T(), codeFormat, code)
		require.Equal(ts.T(), code, crypto.NormalizeRecoveryCode(code))
		seen[code] = true
	}
	require.Len(ts.T(), seen, 10, "codes should be unique")

	factor, err := models.FindFactorByFactorID(ts.API.db, resp.ID)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), models.RecoveryCode, factor.FactorType)
	require.True(ts.T(), factor.IsVerified())
	require.Equal(ts.T(), "My recovery codes", factor.FriendlyName)

	// Every returned plaintext verifies against exactly one stored hash.
	set, err := models.FindRecoveryCodeSetByUser(ts.API.db, ts.TestUser.ID)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), factor.ID, set.MFAFactorID)
	entries, err := models.FindUnusedRecoveryCodes(ts.API.db, set.ID)
	require.NoError(ts.T(), err)
	require.Len(ts.T(), entries, 10)
	for _, code := range resp.Codes {
		matches := 0
		for _, entry := range entries {
			if crypto.CompareHashAndRecoveryCode(entry.CodeHash, code) == nil {
				matches++
			}
		}
		require.Equal(ts.T(), 1, matches, "code %q should match exactly one stored hash", code)
	}

	logs, err := models.FindAuditLogEntries(ts.API.db, []string{"action"}, string(models.RecoveryCodesGeneratedAction), nil)
	require.NoError(ts.T(), err)
	require.Len(ts.T(), logs, 1)
	require.Equal(ts.T(), string(models.RecoveryCodesGeneratedAction), logs[0].Payload["action"])
	require.Equal(ts.T(), "factor", logs[0].Payload["log_type"])
	traits, ok := logs[0].Payload["traits"].(map[string]any)
	require.True(ts.T(), ok)
	require.Equal(ts.T(), factor.ID.String(), traits["factor_id"])
	require.EqualValues(ts.T(), 10, traits["count"])
}

func (ts *RecoveryCodesTestSuite) TestRecoveryCodesGenerateFriendlyName() {
	token := ts.aal2Token()

	cases := []struct {
		desc         string
		body         io.Reader
		expectedName string
	}{
		{desc: "No body", body: nil, expectedName: models.DefaultRecoveryCodeFriendlyName},
		{desc: "Empty object", body: bytes.NewBufferString(`{}`), expectedName: models.DefaultRecoveryCodeFriendlyName},
		{desc: "Whitespace-only name", body: bytes.NewBufferString(`{"friendly_name": "  "}`), expectedName: models.DefaultRecoveryCodeFriendlyName},
		{desc: "Supplied name", body: bytes.NewBufferString(`{"friendly_name": "Backup codes"}`), expectedName: "Backup codes"},
	}

	for _, c := range cases {
		ts.Run(c.desc, func() {
			resp := ts.performGenerate(token, c.body)
			require.Equal(ts.T(), c.expectedName, resp.FriendlyName)

			factor, err := models.FindRecoveryCodeFactorByUser(ts.API.db, ts.TestUser.ID)
			require.NoError(ts.T(), err)
			require.Equal(ts.T(), c.expectedName, factor.FriendlyName)

			// Remove the factor (set and codes cascade) so the next case can
			// generate again.
			require.NoError(ts.T(), ts.API.db.Destroy(factor))
		})
	}
}

func (ts *RecoveryCodesTestSuite) TestRecoveryCodesGenerateEnrollDisabled() {
	ts.Config.MFA.RecoveryCodes.EnrollEnabled = false

	token := ts.aal2Token()
	w := ts.serveRequest(http.MethodPost, "http://localhost/factors/recovery-codes", token, nil)
	ts.requireErrorCode(w, http.StatusUnprocessableEntity, apierrors.ErrorCodeMFARecoveryCodesEnrollDisabled)
}

func (ts *RecoveryCodesTestSuite) TestRecoveryCodesGenerateRequiresAAL2() {
	token := ts.token(ts.TestUser, &ts.TestSession.ID)
	w := ts.serveRequest(http.MethodPost, "http://localhost/factors/recovery-codes", token, nil)
	ts.requireErrorCode(w, http.StatusForbidden, apierrors.ErrorCodeInsufficientAAL)
}

func (ts *RecoveryCodesTestSuite) TestRecoveryCodesGenerateSoleFactor() {
	token := ts.aal2Token()
	// With the TOTP factor unverified, recovery codes would be the sole verified factor.
	require.NoError(ts.T(), ts.TestFactor.UpdateStatus(ts.API.db, models.FactorStateUnverified))

	w := ts.serveRequest(http.MethodPost, "http://localhost/factors/recovery-codes", token, nil)
	ts.requireErrorCode(w, http.StatusUnprocessableEntity, apierrors.ErrorCodeMFARecoveryCodesSoleFactor)
}

func (ts *RecoveryCodesTestSuite) TestRecoveryCodesGenerateAtFactorLimits() {
	token := ts.aal2Token()

	ts.Run("MaxEnrolledFactors", func() {
		ts.Config.MFA.MaxEnrolledFactors = 1
		defer func() { ts.Config.MFA.MaxEnrolledFactors = 10 }()

		w := ts.serveRequest(http.MethodPost, "http://localhost/factors/recovery-codes", token, nil)
		ts.requireErrorCode(w, http.StatusUnprocessableEntity, apierrors.ErrorCodeTooManyEnrolledMFAFactors)
	})

	ts.Run("MaxVerifiedFactors", func() {
		ts.Config.MFA.MaxVerifiedFactors = 1
		defer func() { ts.Config.MFA.MaxVerifiedFactors = 10 }()

		w := ts.serveRequest(http.MethodPost, "http://localhost/factors/recovery-codes", token, nil)
		ts.requireErrorCode(w, http.StatusUnprocessableEntity, apierrors.ErrorCodeTooManyEnrolledMFAFactors)
	})
}

func (ts *RecoveryCodesTestSuite) TestRecoveryCodesGenerateAlreadyEnrolled() {
	token := ts.aal2Token()
	ts.performGenerate(token, nil)

	w := ts.serveRequest(http.MethodPost, "http://localhost/factors/recovery-codes", token, bytes.NewBufferString(`{"friendly_name": "Second set"}`))
	ts.requireErrorCode(w, http.StatusUnprocessableEntity, apierrors.ErrorCodeMFAVerifiedFactorExists)
}

func (ts *RecoveryCodesTestSuite) TestRecoveryCodesGenerateFriendlyNameConflict() {
	token := ts.aal2Token()

	ts.Run("SuppliedNameTaken", func() {
		// The TOTP factor from SetupTest is named "test_factor".
		w := ts.serveRequest(http.MethodPost, "http://localhost/factors/recovery-codes", token, bytes.NewBufferString(`{"friendly_name": "test_factor"}`))
		ts.requireErrorCode(w, http.StatusUnprocessableEntity, apierrors.ErrorCodeMFAFactorNameConflict)
	})

	ts.Run("DefaultNameTaken", func() {
		f := models.NewTOTPFactor(ts.TestUser, models.DefaultRecoveryCodeFriendlyName)
		require.NoError(ts.T(), f.SetSecret("secretkey", ts.Config.Security.DBEncryption.Encrypt, ts.Config.Security.DBEncryption.EncryptionKeyID, ts.Config.Security.DBEncryption.EncryptionKey))
		require.NoError(ts.T(), ts.API.db.Create(f))

		w := ts.serveRequest(http.MethodPost, "http://localhost/factors/recovery-codes", token, nil)
		ts.requireErrorCode(w, http.StatusUnprocessableEntity, apierrors.ErrorCodeMFAFactorNameConflict)
	})
}

func (ts *RecoveryCodesTestSuite) TestRecoveryCodesAnonymousUserForbidden() {
	u, err := models.NewUser("", "", "", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err)
	u.IsAnonymous = true
	require.NoError(ts.T(), ts.API.db.Create(u))

	s, err := models.NewSession(u.ID, nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(s))

	token := ts.token(u, &s.ID)

	w := ts.serveRequest(http.MethodGet, "http://localhost/factors/recovery-codes", token, nil)
	ts.requireErrorCode(w, http.StatusForbidden, apierrors.ErrorCodeNoAuthorization)

	w = ts.serveRequest(http.MethodPost, "http://localhost/factors/recovery-codes", token, nil)
	ts.requireErrorCode(w, http.StatusForbidden, apierrors.ErrorCodeNoAuthorization)
}

func (ts *RecoveryCodesTestSuite) TestRecoveryCodesGenerateEnrolledNotificationEnabled() {
	ts.Config.Mailer.Notifications.MFAFactorEnrolledEnabled = true

	mockMailer, ok := ts.Mailer.(*mockclient.MockMailer)
	require.True(ts.T(), ok, "Mailer is not of type *MockMailer")
	mockMailer.Reset()

	ts.performGenerate(ts.aal2Token(), nil)

	require.Len(ts.T(), mockMailer.MFAFactorEnrolledMailCalls, 1, "Expected one MFA factor enrolled notification email to be sent")
	require.Equal(ts.T(), ts.TestUser.ID, mockMailer.MFAFactorEnrolledMailCalls[0].User.ID, "Email should be sent to the correct user")
	require.Equal(ts.T(), models.RecoveryCode, mockMailer.MFAFactorEnrolledMailCalls[0].FactorType, "Email should specify the correct factor type")
}

func (ts *RecoveryCodesTestSuite) TestRecoveryCodesGenerateEnrolledNotificationDisabled() {
	ts.Config.Mailer.Notifications.MFAFactorEnrolledEnabled = false

	mockMailer, ok := ts.Mailer.(*mockclient.MockMailer)
	require.True(ts.T(), ok, "Mailer is not of type *MockMailer")
	mockMailer.Reset()

	ts.performGenerate(ts.aal2Token(), nil)

	require.Empty(ts.T(), mockMailer.MFAFactorEnrolledMailCalls, "Expected no MFA factor enrolled notification email to be sent")
}

// grantSession creates an AAL1 session through the refresh-token grant flow
func (ts *RecoveryCodesTestSuite) grantSession() *models.Session {
	rt, err := models.GrantAuthenticatedUser(ts.API.db, ts.TestUser, models.GrantParams{})
	require.NoError(ts.T(), err)
	require.NotNil(ts.T(), rt.SessionId)
	session, err := models.FindSessionByID(ts.API.db, *rt.SessionId, false)
	require.NoError(ts.T(), err)
	return session
}

// enrollForVerify generates a recovery-code set at AAL2 on the main test
// session, then returns the generate response plus a fresh AAL1 session
// (verify is issued from AAL1) and a token for it.
func (ts *RecoveryCodesTestSuite) enrollForVerify() (RecoveryCodesResponse, *models.Session, string) {
	resp := ts.performGenerate(ts.aal2Token(), nil)
	session := ts.grantSession()
	return resp, session, ts.token(ts.TestUser, &session.ID)
}

func (ts *RecoveryCodesTestSuite) performVerify(token, code string) *httptest.ResponseRecorder {
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]any{"code": code}))
	return ts.serveRequest(http.MethodPost, "http://localhost/factors/recovery-codes/verify", token, &buffer)
}

// recoveryCodeSetState re-reads the set row so tests can assert on the internal lockout state directly.
func (ts *RecoveryCodesTestSuite) recoveryCodeSetState() *models.RecoveryCodeSet {
	set, err := models.FindRecoveryCodeSetByUser(ts.API.db, ts.TestUser.ID)
	require.NoError(ts.T(), err)
	return set
}

func (ts *RecoveryCodesTestSuite) unusedCodeCount() int {
	entries, err := models.FindUnusedRecoveryCodes(ts.API.db, ts.recoveryCodeSetState().ID)
	require.NoError(ts.T(), err)
	return len(entries)
}

const wrongCode = "aaaaaaaaaaaaa"

func (ts *RecoveryCodesTestSuite) TestRecoveryCodesVerifySuccess() {
	generateResp, verifySession, token := ts.enrollForVerify()

	// A second AAL1 session that must be invalidated by the upgrade.
	secondSession, err := models.NewSession(ts.TestUser.ID, nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(secondSession))

	// Burn one failure first so success resets the counter.
	w := ts.performVerify(token, wrongCode)
	ts.requireErrorCode(w, http.StatusUnprocessableEntity, apierrors.ErrorCodeMFAVerificationFailed)
	require.Equal(ts.T(), 1, ts.recoveryCodeSetState().FailedVerificationCount)

	w = ts.performVerify(token, generateResp.Codes[0])
	require.Equal(ts.T(), http.StatusOK, w.Code)
	tokenResp := &AccessTokenResponse{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(tokenResp))
	require.NotEmpty(ts.T(), tokenResp.Token)
	require.NotEmpty(ts.T(), tokenResp.RefreshToken)

	// The reissued access token is AAL2 with an mfa/recovery_code AMR entry.
	claims := &AccessTokenClaims{}
	_, _, err = jwt.NewParser().ParseUnverified(tokenResp.Token, claims)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), models.AAL2.String(), claims.AuthenticatorAssuranceLevel)
	methods := make([]string, 0, len(claims.AuthenticationMethodReference))
	for _, entry := range claims.AuthenticationMethodReference {
		methods = append(methods, entry.Method)
	}
	require.Contains(ts.T(), methods, models.MFARecoveryCode.String())

	// Code consumed, lockout state reset.
	set := ts.recoveryCodeSetState()
	require.Equal(ts.T(), 0, set.FailedVerificationCount)
	require.Nil(ts.T(), set.VerificationLockedUntil)
	require.Equal(ts.T(), 9, ts.unusedCodeCount())

	// The caller's session was upgraded in place; the other AAL1 session is gone.
	upgraded, err := models.FindSessionByID(ts.API.db, verifySession.ID, false)
	require.NoError(ts.T(), err)
	require.True(ts.T(), upgraded.IsAAL2())
	_, err = models.FindSessionByID(ts.API.db, secondSession.ID, false)
	require.EqualError(ts.T(), err, models.SessionNotFoundError{}.Error())

	logs, err := models.FindAuditLogEntries(ts.API.db, []string{"action"}, string(models.RecoveryCodesVerifiedAction), nil)
	require.NoError(ts.T(), err)
	require.Len(ts.T(), logs, 1)
	require.Equal(ts.T(), "factor", logs[0].Payload["log_type"])
	traits, ok := logs[0].Payload["traits"].(map[string]any)
	require.True(ts.T(), ok)
	require.Equal(ts.T(), generateResp.ID.String(), traits["factor_id"])
	require.EqualValues(ts.T(), 9, traits["remaining"])
}

func (ts *RecoveryCodesTestSuite) TestRecoveryCodesVerifyInputForgiveness() {
	generateResp, _, token := ts.enrollForVerify()

	cases := []struct {
		desc   string
		format func(string) string
	}{
		{desc: "Hyphenated", format: func(c string) string {
			return c[:4] + "-" + c[4:8] + "-" + c[8:12] + "-" + c[12:]
		}},
		{desc: "Spaced", format: func(c string) string {
			return " " + c[:8] + " " + c[8:] + " "
		}},
		{desc: "Uppercase", format: strings.ToUpper},
	}

	for i, c := range cases {
		ts.Run(c.desc, func() {
			w := ts.performVerify(token, c.format(generateResp.Codes[i]))
			require.Equal(ts.T(), http.StatusOK, w.Code)
		})
	}
}

func (ts *RecoveryCodesTestSuite) TestRecoveryCodesVerifyReuseFails() {
	generateResp, _, token := ts.enrollForVerify()

	w := ts.performVerify(token, generateResp.Codes[0])
	require.Equal(ts.T(), http.StatusOK, w.Code)

	// Reusing a consumed code is a failure like any other: uniform error and the counter increments.
	w = ts.performVerify(token, generateResp.Codes[0])
	ts.requireErrorCode(w, http.StatusUnprocessableEntity, apierrors.ErrorCodeMFAVerificationFailed)
	require.Equal(ts.T(), 1, ts.recoveryCodeSetState().FailedVerificationCount)
	require.Equal(ts.T(), 9, ts.unusedCodeCount())
}

func (ts *RecoveryCodesTestSuite) TestRecoveryCodesVerifyUniformFailures() {
	// Absent set: no enrollment yet.
	absentSet := ts.performVerify(ts.token(ts.TestUser, &ts.TestSession.ID), wrongCode)

	generateResp, _, token := ts.enrollForVerify()

	// Wrong code.
	invalid := ts.performVerify(token, wrongCode)

	// Consumed code.
	w := ts.performVerify(token, generateResp.Codes[0])
	require.Equal(ts.T(), http.StatusOK, w.Code)
	consumed := ts.performVerify(token, generateResp.Codes[0])

	// All three failure modes are indistinguishable: same status, identical body bytes.
	for _, recorder := range []*httptest.ResponseRecorder{absentSet, invalid, consumed} {
		require.Equal(ts.T(), http.StatusUnprocessableEntity, recorder.Code)
	}
	require.Equal(ts.T(), absentSet.Body.String(), invalid.Body.String())
	require.Equal(ts.T(), invalid.Body.String(), consumed.Body.String())

	// Failed verifications are not audited; only the one success above is.
	logs, err := models.FindAuditLogEntries(ts.API.db, []string{"action"}, string(models.RecoveryCodesVerifiedAction), nil)
	require.NoError(ts.T(), err)
	require.Len(ts.T(), logs, 1)
}

func (ts *RecoveryCodesTestSuite) TestRecoveryCodesVerifyLockout() {
	ts.Config.MFA.RecoveryCodes.MaxVerifyAttempts = 3

	generateResp, _, token := ts.enrollForVerify()

	for range 3 {
		w := ts.performVerify(token, wrongCode)
		ts.requireErrorCode(w, http.StatusUnprocessableEntity, apierrors.ErrorCodeMFAVerificationFailed)
	}
	set := ts.recoveryCodeSetState()
	require.Equal(ts.T(), 3, set.FailedVerificationCount)
	require.NotNil(ts.T(), set.VerificationLockedUntil)
	lockedUntil := *set.VerificationLockedUntil

	// While locked, even a correct code is rejected without being evaluated and the lock is not extended.
	w := ts.performVerify(token, generateResp.Codes[0])
	ts.requireErrorCode(w, http.StatusTooManyRequests, apierrors.ErrorCodeMFARecoveryCodesLocked)
	set = ts.recoveryCodeSetState()
	require.Equal(ts.T(), 3, set.FailedVerificationCount)
	require.NotNil(ts.T(), set.VerificationLockedUntil)
	require.True(ts.T(), lockedUntil.Equal(*set.VerificationLockedUntil), "lockout must not be extended by attempts while locked")
	require.Equal(ts.T(), 10, ts.unusedCodeCount())

	// Backdate the lock to simulate expiry.
	past := time.Now().Add(-time.Minute)
	set.VerificationLockedUntil = &past
	require.NoError(ts.T(), ts.API.db.UpdateOnly(set, "verification_locked_until"))

	// The first attempt after expiry is processed with a fresh counter.
	w = ts.performVerify(token, wrongCode)
	ts.requireErrorCode(w, http.StatusUnprocessableEntity, apierrors.ErrorCodeMFAVerificationFailed)
	set = ts.recoveryCodeSetState()
	require.Equal(ts.T(), 1, set.FailedVerificationCount)
	require.Nil(ts.T(), set.VerificationLockedUntil)

	// A success after expiry works and resets everything.
	w = ts.performVerify(token, generateResp.Codes[0])
	require.Equal(ts.T(), http.StatusOK, w.Code)
	set = ts.recoveryCodeSetState()
	require.Equal(ts.T(), 0, set.FailedVerificationCount)
	require.Nil(ts.T(), set.VerificationLockedUntil)
}

func (ts *RecoveryCodesTestSuite) setVerificationHook(functionName, functionSQL string) {
	ts.Config.Hook.MFAVerificationAttempt.Enabled = true
	ts.Config.Hook.MFAVerificationAttempt.URI = "pg-functions://postgres/auth/" + functionName
	require.NoError(ts.T(), ts.Config.Hook.MFAVerificationAttempt.PopulateExtensibilityPoint())
	require.NoError(ts.T(), ts.API.db.RawQuery(functionSQL).Exec())
	ts.T().Cleanup(func() {
		require.NoError(ts.T(), ts.API.db.RawQuery(fmt.Sprintf("drop function if exists %s(input jsonb)", functionName)).Exec())
	})
}

func (ts *RecoveryCodesTestSuite) TestRecoveryCodesVerifyHookContinue() {
	ts.setVerificationHook("recovery_codes_hook_continue", `
        create or replace function recovery_codes_hook_continue(input jsonb)
        returns json as $$
        begin
            return json_build_object('decision', 'continue');
        end; $$ language plpgsql;`)

	generateResp, _, token := ts.enrollForVerify()

	w := ts.performVerify(token, generateResp.Codes[0])
	require.Equal(ts.T(), http.StatusOK, w.Code)
	require.Equal(ts.T(), 9, ts.unusedCodeCount())
}

func (ts *RecoveryCodesTestSuite) TestRecoveryCodesVerifyHookRejection() {
	// Rejecting only on the recovery-code factor type also pins the hook payload:
	// if factor_type or factor_id were missing, the hook would continue and the
	// request would succeed, failing this test.
	ts.setVerificationHook("recovery_codes_hook_reject", `
        create or replace function recovery_codes_hook_reject(input jsonb)
        returns json as $$
        begin
            if input->>'factor_type' = 'recovery_code' and input->>'factor_id' is not null then
                return json_build_object('decision', 'reject', 'message', 'recovery code sign-in rejected');
            end if;
            return json_build_object('decision', 'continue');
        end; $$ language plpgsql;`)

	generateResp, _, token := ts.enrollForVerify()

	// A valid code is submitted; the rejection must not consume it.
	w := ts.performVerify(token, generateResp.Codes[0])
	ts.requireErrorCode(w, http.StatusForbidden, apierrors.ErrorCodeMFAVerificationRejected)

	// All the user's sessions are terminated.
	_, err := models.FindSessionByID(ts.API.db, ts.TestSession.ID, false)
	require.EqualError(ts.T(), err, models.SessionNotFoundError{}.Error())

	// No code burned, counter untouched.
	set := ts.recoveryCodeSetState()
	require.Equal(ts.T(), 0, set.FailedVerificationCount)
	require.Nil(ts.T(), set.VerificationLockedUntil)
	require.Equal(ts.T(), 10, ts.unusedCodeCount())
}

func (ts *RecoveryCodesTestSuite) TestRecoveryCodesVerifyHookError() {
	ts.setVerificationHook("recovery_codes_hook_error", `
        create or replace function recovery_codes_hook_error(input jsonb)
        returns json as $$
        begin
            RAISE EXCEPTION 'Intentional Error for Testing';
        end; $$ language plpgsql;`)

	generateResp, _, token := ts.enrollForVerify()

	w := ts.performVerify(token, generateResp.Codes[0])
	require.Equal(ts.T(), http.StatusInternalServerError, w.Code)

	// The request failed before the transaction: nothing consumed, nothing counted.
	set := ts.recoveryCodeSetState()
	require.Equal(ts.T(), 0, set.FailedVerificationCount)
	require.Equal(ts.T(), 10, ts.unusedCodeCount())
}

func (ts *RecoveryCodesTestSuite) TestRecoveryCodesVerifyHookSkippedWhenNoSet() {
	ts.setVerificationHook("recovery_codes_hook_reject_all", `
        create or replace function recovery_codes_hook_reject_all(input jsonb)
        returns json as $$
        begin
            return json_build_object('decision', 'reject');
        end; $$ language plpgsql;`)

	// No set enrolled: the uniform failure is returned without invoking the
	// hook, so no rejection (and no logout) can happen.
	token := ts.token(ts.TestUser, &ts.TestSession.ID)
	w := ts.performVerify(token, wrongCode)
	ts.requireErrorCode(w, http.StatusUnprocessableEntity, apierrors.ErrorCodeMFAVerificationFailed)

	_, err := models.FindSessionByID(ts.API.db, ts.TestSession.ID, false)
	require.NoError(ts.T(), err, "sessions must survive when the hook is skipped")
}

func (ts *RecoveryCodesTestSuite) TestRecoveryCodesVerifyCrossUserIsolation() {
	// Enroll the test user.
	_, _, token := ts.enrollForVerify()

	// A second user with their own verified factor, session, and codes.
	otherUser, err := models.NewUser("", "other@example.com", "password", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(otherUser))
	otherFactor := models.NewTOTPFactor(otherUser, "other_factor")
	require.NoError(ts.T(), otherFactor.SetSecret("secretkey", ts.Config.Security.DBEncryption.Encrypt, ts.Config.Security.DBEncryption.EncryptionKeyID, ts.Config.Security.DBEncryption.EncryptionKey))
	require.NoError(ts.T(), ts.API.db.Create(otherFactor))
	require.NoError(ts.T(), otherFactor.UpdateStatus(ts.API.db, models.FactorStateVerified))
	otherSession, err := models.NewSession(otherUser.ID, &otherFactor.ID)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(otherSession))
	require.NoError(ts.T(), otherSession.UpdateAALAndAssociatedFactor(ts.API.db, models.AAL2, &otherFactor.ID))
	otherResp := ts.performGenerate(ts.token(otherUser, &otherSession.ID), nil)

	// The test user submits the other user's valid code: uniform failure, the
	// test user's counter increments, and the other user's code stays unused.
	w := ts.performVerify(token, otherResp.Codes[0])
	ts.requireErrorCode(w, http.StatusUnprocessableEntity, apierrors.ErrorCodeMFAVerificationFailed)

	require.Equal(ts.T(), 1, ts.recoveryCodeSetState().FailedVerificationCount)

	otherSet, err := models.FindRecoveryCodeSetByUser(ts.API.db, otherUser.ID)
	require.NoError(ts.T(), err)
	otherEntries, err := models.FindUnusedRecoveryCodes(ts.API.db, otherSet.ID)
	require.NoError(ts.T(), err)
	require.Len(ts.T(), otherEntries, 10)
	require.Equal(ts.T(), 0, otherSet.FailedVerificationCount)
}

func (ts *RecoveryCodesTestSuite) TestRecoveryCodesVerifyDisabled() {
	ts.Config.MFA.RecoveryCodes.VerifyEnabled = false

	generateResp, _, token := ts.enrollForVerify()
	w := ts.performVerify(token, generateResp.Codes[0])
	ts.requireErrorCode(w, http.StatusUnprocessableEntity, apierrors.ErrorCodeMFARecoveryCodesVerifyDisabled)
}

func (ts *RecoveryCodesTestSuite) TestRecoveryCodesVerifyBadInput() {
	_, _, token := ts.enrollForVerify()

	cases := []struct {
		desc string
		body io.Reader
	}{
		{desc: "Missing body", body: nil},
		{desc: "Empty code", body: bytes.NewBufferString(`{"code": ""}`)},
		{desc: "Separators-only code", body: bytes.NewBufferString(`{"code": " -- - "}`)},
	}

	for _, c := range cases {
		ts.Run(c.desc, func() {
			w := ts.serveRequest(http.MethodPost, "http://localhost/factors/recovery-codes/verify", token, c.body)
			require.Equal(ts.T(), http.StatusBadRequest, w.Code)
		})
	}

	// Malformed input never reaches the failure counter.
	require.Equal(ts.T(), 0, ts.recoveryCodeSetState().FailedVerificationCount)
}
