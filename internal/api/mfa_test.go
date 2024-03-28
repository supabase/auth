package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofrs/uuid"

	"database/sql"
	"github.com/pkg/errors"
	"github.com/pquerna/otp"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/utilities"

	"github.com/jackc/pgx/v4"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type MFATestSuite struct {
	suite.Suite
	API                  *API
	Config               *conf.GlobalConfiguration
	TestDomain           string
	TestEmail            string
	TestOTPKey           *otp.Key
	TestPassword         string
	TestUser             *models.User
	TestSession          *models.Session
	TestSecondarySession *models.Session
}

func TestMFA(t *testing.T) {
	api, config, err := setupAPIForTest()
	require.NoError(t, err)
	ts := &MFATestSuite{
		API:    api,
		Config: config,
	}
	defer api.db.Close()
	suite.Run(t, ts)
}

func (ts *MFATestSuite) SetupTest() {
	models.TruncateAll(ts.API.db)

	ts.TestEmail = "test@example.com"
	ts.TestPassword = "password"
	// Create user
	u, err := models.NewUser("123456789", ts.TestEmail, ts.TestPassword, ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err, "Error creating test user model")
	require.NoError(ts.T(), ts.API.db.Create(u), "Error saving new test user")
	// Create Factor
	f := models.NewFactor(u, "test_factor", models.TOTP, models.FactorStateUnverified, "secretkey")
	require.NoError(ts.T(), ts.API.db.Create(f), "Error saving new test factor")
	// Create corresponding session
	s, err := models.NewSession(u.ID, &f.ID)
	require.NoError(ts.T(), err, "Error creating test session")
	require.NoError(ts.T(), ts.API.db.Create(s), "Error saving test session")

	u, err = models.FindUserByEmailAndAudience(ts.API.db, ts.TestEmail, ts.Config.JWT.Aud)
	ts.Require().NoError(err)

	ts.TestUser = u
	ts.TestSession = s

	secondarySession, err := models.NewSession(ts.TestUser.ID, &f.ID)
	require.NoError(ts.T(), err, "Error creating test session")
	require.NoError(ts.T(), ts.API.db.Create(secondarySession), "Error saving test session")

	ts.TestSecondarySession = secondarySession

	// Generate TOTP related settings
	testDomain := strings.Split(ts.TestEmail, "@")[1]
	ts.TestDomain = testDomain

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      ts.TestDomain,
		AccountName: ts.TestEmail,
	})
	require.NoError(ts.T(), err)
	ts.TestOTPKey = key

}

func (ts *MFATestSuite) generateAAL1Token(user *models.User, sessionId *uuid.UUID) string {
	token, _, err := ts.API.generateAccessToken(context.Background(), ts.API.db, user, sessionId, models.TOTPSignIn)
	require.NoError(ts.T(), err, "Error generating access token")
	return token
}

func (ts *MFATestSuite) TestEnrollFactor() {
	testFriendlyName := "bob"
	alternativeFriendlyName := "john"

	token := ts.generateAAL1Token(ts.TestUser, &ts.TestSession.ID)

	var cases = []struct {
		desc         string
		friendlyName string
		factorType   string
		issuer       string
		expectedCode int
	}{
		{
			desc:         "TOTP: No issuer",
			friendlyName: alternativeFriendlyName,
			factorType:   models.TOTP,
			issuer:       "",
			expectedCode: http.StatusOK,
		},
		{
			desc:         "Invalid factor type",
			friendlyName: testFriendlyName,
			factorType:   "invalid_factor",
			issuer:       ts.TestDomain,
			expectedCode: http.StatusBadRequest,
		},
		{
			desc:         "TOTP: Factor has friendly name",
			friendlyName: testFriendlyName,
			factorType:   models.TOTP,
			issuer:       ts.TestDomain,
			expectedCode: http.StatusOK,
		},
		{
			desc:         "TOTP: Enrolling without friendly name",
			friendlyName: "",
			factorType:   models.TOTP,
			issuer:       ts.TestDomain,
			expectedCode: http.StatusOK,
		},
	}
	for _, c := range cases {
		ts.Run(c.desc, func() {
			w := performEnrollFlow(ts, token, c.friendlyName, c.factorType, c.issuer, c.expectedCode)

			factors, err := FindFactorsByUser(ts.API.db, ts.TestUser)
			ts.Require().NoError(err)
			addedFactor := factors[len(factors)-1]
			require.False(ts.T(), addedFactor.IsVerified())
			if c.friendlyName != "" && c.expectedCode == http.StatusOK {
				require.Equal(ts.T(), c.friendlyName, addedFactor.FriendlyName)
			}

			if w.Code == http.StatusOK {
				enrollResp := EnrollFactorResponse{}
				require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&enrollResp))
				qrCode := enrollResp.TOTP.QRCode
				hasSVGStartAndEnd := strings.Contains(qrCode, "<svg") && strings.Contains(qrCode, "</svg>")
				require.True(ts.T(), hasSVGStartAndEnd)
				require.Equal(ts.T(), c.friendlyName, enrollResp.FriendlyName)
			}
		})
	}
}

func (ts *MFATestSuite) TestDuplicateEnrollsReturnExpectedMessage() {
	friendlyName := "mary"
	issuer := "https://issuer.com"
	token := ts.generateAAL1Token(ts.TestUser, &ts.TestSession.ID)
	_ = performEnrollFlow(ts, token, friendlyName, models.TOTP, issuer, http.StatusOK)
	response := performEnrollFlow(ts, token, friendlyName, models.TOTP, issuer, http.StatusUnprocessableEntity)

	var errorResponse HTTPError
	err := json.NewDecoder(response.Body).Decode(&errorResponse)
	require.NoError(ts.T(), err)

	// Convert the response body to a string and check for the expected error message
	expectedErrorMessage := fmt.Sprintf("A factor with the friendly name %q for this user likely already exists", friendlyName)
	require.Contains(ts.T(), errorResponse.Message, expectedErrorMessage)
}

func (ts *MFATestSuite) TestMultipleEnrollsCleanupExpiredFactors() {
	// All factors are deleted when a subsequent enroll is made
	ts.API.config.MFA.FactorExpiryDuration = 0 * time.Second
	// Verified factor should not be deleted (Factor 1)
	resp := performTestSignupAndVerify(ts, ts.TestEmail, ts.TestPassword, true /* <- requireStatusOK */)
	numFactors := 5
	accessTokenResp := &AccessTokenResponse{}
	require.NoError(ts.T(), json.NewDecoder(resp.Body).Decode(&accessTokenResp))

	token := accessTokenResp.Token
	for i := 0; i < numFactors; i++ {
		_ = performEnrollFlow(ts, token, "", models.TOTP, "https://issuer.com", http.StatusOK)
	}

	// All Factors except last factor should be expired
	factors, err := FindFactorsByUser(ts.API.db, ts.TestUser)
	require.NoError(ts.T(), err)

	// Make a challenge so last, unverified factor isn't deleted on next enroll (Factor 2)
	_ = performChallengeFlow(ts, factors[len(factors)-1].ID, token)

	// Enroll another Factor (Factor 3)
	_ = performEnrollFlow(ts, token, "", models.TOTP, "https://issuer.com", http.StatusOK)
	factors, err = FindFactorsByUser(ts.API.db, ts.TestUser)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), 3, len(factors))
}

func (ts *MFATestSuite) TestChallengeFactor() {
	f := ts.TestUser.Factors[0]
	token := ts.generateAAL1Token(ts.TestUser, &ts.TestSession.ID)
	w := performChallengeFlow(ts, f.ID, token)
	require.Equal(ts.T(), http.StatusOK, w.Code)
}

func (ts *MFATestSuite) TestMFAVerifyFactor() {
	cases := []struct {
		desc             string
		validChallenge   bool
		validCode        bool
		expectedHTTPCode int
	}{
		{
			desc:             "Invalid: Valid code and expired challenge",
			validChallenge:   false,
			validCode:        true,
			expectedHTTPCode: http.StatusUnprocessableEntity,
		},
		{
			desc:             "Invalid: Invalid code and valid challenge ",
			validChallenge:   true,
			validCode:        false,
			expectedHTTPCode: http.StatusUnprocessableEntity,
		},
		{
			desc:             "Valid /verify request",
			validChallenge:   true,
			validCode:        true,
			expectedHTTPCode: http.StatusOK,
		},
	}
	for _, v := range cases {
		ts.Run(v.desc, func() {
			// Authenticate users and set secret
			var buffer bytes.Buffer
			r, err := models.GrantAuthenticatedUser(ts.API.db, ts.TestUser, models.GrantParams{})
			require.NoError(ts.T(), err)

			sharedSecret := ts.TestOTPKey.Secret()
			factors, err := FindFactorsByUser(ts.API.db, ts.TestUser)
			f := factors[0]
			f.Secret = sharedSecret
			require.NoError(ts.T(), err)
			require.NoError(ts.T(), ts.API.db.Update(f), "Error updating new test factor")

			token := ts.generateAAL1Token(ts.TestUser, r.SessionId)
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/factors/%s/verify", f.ID), &buffer)
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

			testIPAddress := utilities.GetIPAddress(req)
			c := models.NewChallenge(f, testIPAddress)
			require.NoError(ts.T(), ts.API.db.Create(c), "Error saving new test challenge")
			if !v.validChallenge {
				// Set challenge creation so that it has expired in present time.
				newCreatedAt := time.Now().UTC().Add(-1 * time.Second * time.Duration(ts.Config.MFA.ChallengeExpiryDuration+1))
				// created_at is managed by buffalo(ORM) needs to be raw query to be updated
				err := ts.API.db.RawQuery("UPDATE auth.mfa_challenges SET created_at = ? WHERE factor_id = ?", newCreatedAt, f.ID).Exec()
				require.NoError(ts.T(), err, "Error updating new test challenge")
			}

			// Verify TOTP code
			code, err := totp.GenerateCode(sharedSecret, time.Now().UTC())
			if !v.validCode {
				// Use an inaccurate time, resulting in an invalid code(usually)
				code, err = totp.GenerateCode(sharedSecret, time.Now().UTC().Add(-1*time.Minute*time.Duration(1)))
			}
			require.NoError(ts.T(), err)
			require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
				"challenge_id": c.ID,
				"code":         code,
			}))

			ts.API.handler.ServeHTTP(w, req)
			require.Equal(ts.T(), v.expectedHTTPCode, w.Code)

			if v.expectedHTTPCode == http.StatusOK {
				// Ensure alternate session has been deleted
				_, err = models.FindSessionByID(ts.API.db, ts.TestSecondarySession.ID, false)
				require.EqualError(ts.T(), err, models.SessionNotFoundError{}.Error())
			}
			if !v.validChallenge {
				// Ensure invalid challenges are deleted
				_, err := models.FindChallengeByID(ts.API.db, c.ID)
				require.EqualError(ts.T(), err, models.ChallengeNotFoundError{}.Error())
			}
		})
	}
}

func (ts *MFATestSuite) TestUnenrollVerifiedFactor() {
	cases := []struct {
		desc             string
		isAAL2           bool
		expectedHTTPCode int
	}{
		{
			desc:             "Verified Factor: AAL1",
			isAAL2:           false,
			expectedHTTPCode: http.StatusUnprocessableEntity,
		},
		{
			desc:             "Verified Factor: AAL2, Success",
			isAAL2:           true,
			expectedHTTPCode: http.StatusOK,
		},
	}
	for _, v := range cases {
		ts.Run(v.desc, func() {
			var buffer bytes.Buffer

			// Create Session to test behaviour which downgrades other sessions
			factors, err := FindFactorsByUser(ts.API.db, ts.TestUser)
			require.NoError(ts.T(), err, "error finding factors")
			f := factors[0]
			f.Secret = ts.TestOTPKey.Secret()
			require.NoError(ts.T(), f.UpdateStatus(ts.API.db, models.FactorStateVerified))
			require.NoError(ts.T(), ts.API.db.Update(f), "Error updating new test factor")
			if v.isAAL2 {
				ts.TestSession.UpdateAALAndAssociatedFactor(ts.API.db, models.AAL2, &f.ID)
			}
			token := ts.generateAAL1Token(ts.TestUser, &ts.TestSession.ID)
			w := ServeAuthenticatedRequest(ts, http.MethodDelete, fmt.Sprintf("/factors/%s", f.ID), token, buffer)
			require.Equal(ts.T(), v.expectedHTTPCode, w.Code)

			if v.expectedHTTPCode == http.StatusOK {
				_, err := models.FindFactorByFactorID(ts.API.db, f.ID)
				require.EqualError(ts.T(), err, models.FactorNotFoundError{}.Error())
				session, _ := models.FindSessionByID(ts.API.db, ts.TestSecondarySession.ID, false)
				require.Equal(ts.T(), models.AAL1.String(), session.GetAAL())
				require.Nil(ts.T(), session.FactorID)

			}
		})
	}

}

func (ts *MFATestSuite) TestUnenrollUnverifiedFactor() {
	var buffer bytes.Buffer
	f := ts.TestUser.Factors[0]
	f.Secret = ts.TestOTPKey.Secret()

	token := ts.generateAAL1Token(ts.TestUser, &ts.TestSession.ID)
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"factor_id": f.ID,
	}))

	w := ServeAuthenticatedRequest(ts, http.MethodDelete, fmt.Sprintf("/factors/%s", f.ID), token, buffer)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	_, err := models.FindFactorByFactorID(ts.API.db, f.ID)
	require.EqualError(ts.T(), err, models.FactorNotFoundError{}.Error())
	session, _ := models.FindSessionByID(ts.API.db, ts.TestSecondarySession.ID, false)
	require.Equal(ts.T(), models.AAL1.String(), session.GetAAL())
	require.Nil(ts.T(), session.FactorID)

}

// Integration Tests
func (ts *MFATestSuite) TestSessionsMaintainAALOnRefresh() {
	ts.Config.Security.RefreshTokenRotationEnabled = true
	resp := performTestSignupAndVerify(ts, ts.TestEmail, ts.TestPassword, true /* <- requireStatusOK */)
	accessTokenResp := &AccessTokenResponse{}
	require.NoError(ts.T(), json.NewDecoder(resp.Body).Decode(&accessTokenResp))

	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"refresh_token": accessTokenResp.RefreshToken,
	}))

	req := httptest.NewRequest(http.MethodPost, "http://localhost/token?grant_type=refresh_token", &buffer)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	data := &AccessTokenResponse{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))

	ctx, err := ts.API.parseJWTClaims(data.Token, req)
	require.NoError(ts.T(), err)
	ctx, err = ts.API.maybeLoadUserOrSession(ctx)
	require.NoError(ts.T(), err)
	require.True(ts.T(), getSession(ctx).IsAAL2())
}

// Performing MFA Verification followed by a sign in should return an AAL1 session and an AAL2 session
func (ts *MFATestSuite) TestMFAFollowedByPasswordSignIn() {
	ts.Config.Security.RefreshTokenRotationEnabled = true
	resp := performTestSignupAndVerify(ts, ts.TestEmail, ts.TestPassword, true /* <- requireStatusOK */)
	accessTokenResp := &AccessTokenResponse{}
	require.NoError(ts.T(), json.NewDecoder(resp.Body).Decode(&accessTokenResp))

	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"email":    ts.TestEmail,
		"password": ts.TestPassword,
	}))
	req := httptest.NewRequest(http.MethodPost, "http://localhost/token?grant_type=password", &buffer)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	data := &AccessTokenResponse{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))
	ctx, err := ts.API.parseJWTClaims(data.Token, req)
	require.NoError(ts.T(), err)

	ctx, err = ts.API.maybeLoadUserOrSession(ctx)
	require.NoError(ts.T(), err)

	require.Equal(ts.T(), models.AAL1.String(), getSession(ctx).GetAAL())
	session, err := models.FindSessionByUserID(ts.API.db, accessTokenResp.User.ID)
	require.NoError(ts.T(), err)
	require.True(ts.T(), session.IsAAL2())
}

func signUp(ts *MFATestSuite, email, password string) (signUpResp AccessTokenResponse) {
	ts.API.config.Mailer.Autoconfirm = true
	var buffer bytes.Buffer

	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"email":    email,
		"password": password,
	}))

	// Setup request
	req := httptest.NewRequest(http.MethodPost, "http://localhost/signup", &buffer)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)
	data := AccessTokenResponse{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))
	return data
}

func performTestSignupAndVerify(ts *MFATestSuite, email, password string, requireStatusOK bool) *httptest.ResponseRecorder {
	signUpResp := signUp(ts, email, password)
	resp := performEnrollAndVerify(ts, signUpResp.Token, requireStatusOK)

	return resp

}

func performEnrollFlow(ts *MFATestSuite, token, friendlyName, factorType, issuer string, expectedCode int) *httptest.ResponseRecorder {
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(EnrollFactorParams{FriendlyName: friendlyName, FactorType: factorType, Issuer: issuer}))
	w := ServeAuthenticatedRequest(ts, http.MethodPost, "http://localhost/factors/", token, buffer)
	require.Equal(ts.T(), expectedCode, w.Code)
	return w
}

func ServeAuthenticatedRequest(ts *MFATestSuite, method, path, token string, buffer bytes.Buffer) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, &buffer)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	ts.API.handler.ServeHTTP(w, req)
	return w
}

func performVerifyFlow(ts *MFATestSuite, challengeID, factorID uuid.UUID, token string, requireStatusOK bool) *httptest.ResponseRecorder {
	var buffer bytes.Buffer

	conn, err := pgx.Connect(context.Background(), ts.API.db.URL())
	require.NoError(ts.T(), err)

	defer conn.Close(context.Background())

	var totpSecret string
	err = conn.QueryRow(context.Background(), "select secret from mfa_factors where id=$1", factorID).Scan(&totpSecret)
	require.NoError(ts.T(), err)

	code, err := totp.GenerateCode(totpSecret, time.Now().UTC())
	require.NoError(ts.T(), err)

	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"challenge_id": challengeID,
		"code":         code,
	}))

	y := ServeAuthenticatedRequest(ts, http.MethodPost, fmt.Sprintf("/factors/%s/verify", factorID), token, buffer)

	if requireStatusOK {
		require.Equal(ts.T(), http.StatusOK, y.Code)
	}
	return y
}

func performChallengeFlow(ts *MFATestSuite, factorID uuid.UUID, token string) *httptest.ResponseRecorder {
	var buffer bytes.Buffer
	w := ServeAuthenticatedRequest(ts, http.MethodPost, fmt.Sprintf("http://localhost/factors/%s/challenge", factorID), token, buffer)
	require.Equal(ts.T(), http.StatusOK, w.Code)
	return w

}

func performEnrollAndVerify(ts *MFATestSuite, token string, requireStatusOK bool) *httptest.ResponseRecorder {
	w := performEnrollFlow(ts, token, "", models.TOTP, ts.TestDomain, http.StatusOK)
	enrollResp := EnrollFactorResponse{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&enrollResp))
	factorID := enrollResp.ID

	// Challenge
	w = performChallengeFlow(ts, factorID, token)

	challengeResp := EnrollFactorResponse{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&challengeResp))
	challengeID := challengeResp.ID

	// Verify
	y := performVerifyFlow(ts, challengeID, factorID, token, requireStatusOK)

	return y
}

func (ts *MFATestSuite) TestVerificationHooks() {
	type verificationHookTestCase struct {
		desc                string
		enabled             bool
		uri                 string
		hookFunctionSQL     string
		emailSuffix         string
		expectToken         bool
		expectedCode        int
		cleanupHookFunction string
	}
	cases := []verificationHookTestCase{
		{
			desc:    "Default Success",
			enabled: true,
			uri:     "pg-functions://postgres/auth/verification_hook",
			hookFunctionSQL: `
                create or replace function verification_hook(input jsonb)
                returns json as $$
                begin
                    return json_build_object('decision', 'continue');
                end; $$ language plpgsql;`,
			emailSuffix:         "success",
			expectToken:         true,
			expectedCode:        http.StatusOK,
			cleanupHookFunction: "verification_hook(input jsonb)",
		},
		{
			desc:    "Error",
			enabled: true,
			uri:     "pg-functions://postgres/auth/test_verification_hook_error",
			hookFunctionSQL: `
                create or replace function test_verification_hook_error(input jsonb)
                returns json as $$
                begin
                    RAISE EXCEPTION 'Intentional Error for Testing';
                end; $$ language plpgsql;`,
			emailSuffix:         "error",
			expectToken:         false,
			expectedCode:        http.StatusInternalServerError,
			cleanupHookFunction: "test_verification_hook_error(input jsonb)",
		},
		{
			desc:    "Reject - Enabled",
			enabled: true,
			uri:     "pg-functions://postgres/auth/verification_hook_reject",
			hookFunctionSQL: `
        create or replace function verification_hook_reject(input jsonb)
        returns json as $$
        begin
            return json_build_object(
                'decision', 'reject',
                'message', 'authentication attempt rejected'
            );
        end; $$ language plpgsql;`,
			emailSuffix:         "reject_enabled",
			expectToken:         false,
			expectedCode:        http.StatusForbidden,
			cleanupHookFunction: "verification_hook_reject(input jsonb)",
		},
		{
			desc:    "Reject - Disabled",
			enabled: false,
			uri:     "pg-functions://postgres/auth/verification_hook_reject",
			hookFunctionSQL: `
        create or replace function verification_hook_reject(input jsonb)
        returns json as $$
        begin
            return json_build_object(
                'decision', 'reject',
                'message', 'authentication attempt rejected'
            );
        end; $$ language plpgsql;`,
			emailSuffix:         "reject_disabled",
			expectToken:         true,
			expectedCode:        http.StatusOK,
			cleanupHookFunction: "verification_hook_reject(input jsonb)",
		},
		{
			desc:    "Timeout",
			enabled: true,
			uri:     "pg-functions://postgres/auth/test_verification_hook_timeout",
			hookFunctionSQL: `
        create or replace function test_verification_hook_timeout(input jsonb)
        returns json as $$
        begin
            PERFORM pg_sleep(3);
            return json_build_object(
                'decision', 'continue'
            );
        end; $$ language plpgsql;`,
			emailSuffix:         "timeout",
			expectToken:         false,
			expectedCode:        http.StatusInternalServerError,
			cleanupHookFunction: "test_verification_hook_timeout(input jsonb)",
		},
	}

	for _, c := range cases {
		ts.T().Run(c.desc, func(t *testing.T) {
			ts.Config.Hook.MFAVerificationAttempt.Enabled = c.enabled
			ts.Config.Hook.MFAVerificationAttempt.URI = c.uri
			require.NoError(ts.T(), ts.Config.Hook.MFAVerificationAttempt.PopulateExtensibilityPoint())

			err := ts.API.db.RawQuery(c.hookFunctionSQL).Exec()
			require.NoError(t, err)

			email := fmt.Sprintf("testemail_%s@gmail.com", c.emailSuffix)
			password := "testpassword"
			resp := performTestSignupAndVerify(ts, email, password, c.expectToken)
			require.Equal(ts.T(), c.expectedCode, resp.Code)
			accessTokenResp := &AccessTokenResponse{}
			require.NoError(ts.T(), json.NewDecoder(resp.Body).Decode(&accessTokenResp))

			if c.expectToken {
				require.NotEqual(t, "", accessTokenResp.Token)
			} else {
				require.Equal(t, "", accessTokenResp.Token)
			}

			cleanupHook(ts, c.cleanupHookFunction)
		})
	}
}

func cleanupHook(ts *MFATestSuite, hookName string) {
	cleanupHookSQL := fmt.Sprintf("drop function if exists %s", hookName)
	err := ts.API.db.RawQuery(cleanupHookSQL).Exec()
	require.NoError(ts.T(), err)
}

// FindFactorsByUser returns all factors belonging to a user ordered by timestamp. Don't use this outside of tests.
func FindFactorsByUser(tx *storage.Connection, user *models.User) ([]*models.Factor, error) {
	factors := []*models.Factor{}
	if err := tx.Q().Where("user_id = ?", user.ID).Order("created_at asc").All(&factors); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return factors, nil
		}
		return nil, errors.Wrap(err, "Database error when finding MFA factors associated to user")
	}
	return factors, nil
}
