package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/gofrs/uuid"
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
	ts.Config.MFA.MaxEnrolledFactors = 10
	ts.Config.MFA.MaxVerifiedFactors = 10
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
