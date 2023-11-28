package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/gofrs/uuid"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/supabase/gotrue/internal/conf"
	"github.com/supabase/gotrue/internal/models"
	"github.com/supabase/gotrue/internal/utilities"

	"github.com/jackc/pgx/v4"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type MFATestSuite struct {
	suite.Suite
	API          *API
	Config       *conf.GlobalConfiguration
	TestDomain   string
	TestEmail    string
	TestOTPKey   *otp.Key
	TestPassword string
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
	// Create user
	u, err := models.NewUser("123456789", "test@example.com", "password", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err, "Error creating test user model")
	require.NoError(ts.T(), ts.API.db.Create(u), "Error saving new test user")
	// Create Factor
	f, err := models.NewFactor(u, "test_factor", models.TOTP, models.FactorStateUnverified, "secretkey")
	require.NoError(ts.T(), err, "Error creating test factor model")
	require.NoError(ts.T(), ts.API.db.Create(f), "Error saving new test factor")
	// Create corresponding session
	s, err := models.NewSession()
	require.NoError(ts.T(), err, "Error creating test session")
	s.UserID = u.ID
	s.FactorID = &f.ID
	require.NoError(ts.T(), ts.API.db.Create(s), "Error saving test session")

	// Generate TOTP related settings
	emailValue, err := u.Email.Value()
	require.NoError(ts.T(), err)
	testEmail := emailValue.(string)
	testDomain := strings.Split(testEmail, "@")[1]
	ts.TestDomain = testDomain
	ts.TestEmail = testEmail
	ts.TestPassword = "password"

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      ts.TestDomain,
		AccountName: ts.TestEmail,
	})
	require.NoError(ts.T(), err)
	ts.TestOTPKey = key

}

func (ts *MFATestSuite) TestEnrollFactor() {
	testFriendlyName := "bob"
	alternativeFriendlyName := "john"
	user, err := models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	ts.Require().NoError(err)

	token, _, err := generateAccessToken(ts.API.db, user, nil, &ts.Config.JWT)

	require.NoError(ts.T(), err)
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

			factors, err := models.FindFactorsByUser(ts.API.db, user)
			ts.Require().NoError(err)
			latestFactor := factors[len(factors)-1]
			require.False(ts.T(), latestFactor.IsVerified())
			if c.friendlyName != "" && c.expectedCode == http.StatusOK {
				require.Equal(ts.T(), c.friendlyName, latestFactor.FriendlyName)
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

func (ts *MFATestSuite) TestChallengeFactor() {
	u, err := models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)

	factors, err := models.FindFactorsByUser(ts.API.db, u)
	require.NoError(ts.T(), err)
	f := factors[0]

	token, _, err := generateAccessToken(ts.API.db, u, nil, &ts.Config.JWT)
	require.NoError(ts.T(), err, "Error generating access token")

	var buffer bytes.Buffer
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("http://localhost/factors/%s/challenge", f.ID), &buffer)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)
}

func (ts *MFATestSuite) TestMFAVerifyFactor() {
	user, err := models.FindUserByEmailAndAudience(ts.API.db, ts.TestEmail, ts.Config.JWT.Aud)
	ts.Require().NoError(err)
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
			expectedHTTPCode: http.StatusBadRequest,
		},
		{
			desc:             "Invalid: Invalid code and valid challenge ",
			validChallenge:   true,
			validCode:        false,
			expectedHTTPCode: http.StatusBadRequest,
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
			r, err := models.GrantAuthenticatedUser(ts.API.db, user, models.GrantParams{})
			require.NoError(ts.T(), err)
			sharedSecret := ts.TestOTPKey.Secret()
			factors, err := models.FindFactorsByUser(ts.API.db, user)
			f := factors[0]
			f.Secret = sharedSecret
			require.NoError(ts.T(), err)
			require.NoError(ts.T(), ts.API.db.Update(f), "Error updating new test factor")

			// Create session to be invalidated
			secondarySession, err := models.NewSession()
			require.NoError(ts.T(), err, "Error creating test session")
			secondarySession.UserID = user.ID
			secondarySession.FactorID = &f.ID
			require.NoError(ts.T(), ts.API.db.Create(secondarySession), "Error saving test session")

			token, _, err := generateAccessToken(ts.API.db, user, r.SessionId, &ts.Config.JWT)

			require.NoError(ts.T(), err)

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/factors/%s/verify", f.ID), &buffer)
			testIPAddress := utilities.GetIPAddress(req)
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
			c, err := models.NewChallenge(f, testIPAddress)
			require.NoError(ts.T(), err, "Error creating test Challenge model")
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
				_, err = models.FindSessionByID(ts.API.db, secondarySession.ID, false)
				require.EqualError(ts.T(), err, models.SessionNotFoundError{}.Error())
			}
			if !v.validChallenge {
				// Ensure invalid challenges are deleted
				_, err := models.FindChallengeByChallengeID(ts.API.db, c.ID)
				require.EqualError(ts.T(), err, models.ChallengeNotFoundError{}.Error())
			}
		})
	}
}

func (ts *MFATestSuite) setupUserAndSession() (*models.User, *models.Session) {
	user, err := models.FindUserByEmailAndAudience(ts.API.db, ts.TestEmail, ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	session, err := models.FindSessionByUserID(ts.API.db, user.ID)
	require.NoError(ts.T(), err)
	return user, session
}

func (ts *MFATestSuite) TestUnenrollVerifiedFactor() {
	user, session := ts.setupUserAndSession()

	cases := []struct {
		desc             string
		isAAL2           bool
		expectedHTTPCode int
	}{
		{
			desc:             "Verified Factor: AAL1",
			isAAL2:           false,
			expectedHTTPCode: http.StatusBadRequest,
		},
		{
			desc:             "Verified Factor: AAL2, Success",
			isAAL2:           true,
			expectedHTTPCode: http.StatusOK,
		},
	}
	for _, v := range cases {
		ts.Run(v.desc, func() {
			// Create User
			if v.isAAL2 {
				session.UpdateAssociatedAAL(ts.API.db, models.AAL2.String())
			}
			var secondarySession *models.Session

			// Create Session to test behaviour which downgrades other sessions
			factors, err := models.FindFactorsByUser(ts.API.db, user)
			require.NoError(ts.T(), err, "error finding factors")
			f := factors[0]
			secondarySession, err = models.NewSession()
			require.NoError(ts.T(), err, "Error creating test session")
			secondarySession.UserID = user.ID
			secondarySession.FactorID = &f.ID
			require.NoError(ts.T(), ts.API.db.Create(secondarySession), "Error saving test session")

			sharedSecret := ts.TestOTPKey.Secret()
			f.Secret = sharedSecret
			err = f.UpdateStatus(ts.API.db, models.FactorStateVerified)
			require.NoError(ts.T(), err)
			require.NoError(ts.T(), ts.API.db.Update(f), "Error updating new test factor")

			var buffer bytes.Buffer

			token, _, err := generateAccessToken(ts.API.db, user, &session.ID, &ts.Config.JWT)
			require.NoError(ts.T(), err)

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/factors/%s/", f.ID), &buffer)
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
			ts.API.handler.ServeHTTP(w, req)
			require.Equal(ts.T(), v.expectedHTTPCode, w.Code)

			if v.expectedHTTPCode == http.StatusOK {
				_, err = models.FindFactorByFactorID(ts.API.db, f.ID)
				require.EqualError(ts.T(), err, models.FactorNotFoundError{}.Error())
				session, _ := models.FindSessionByID(ts.API.db, secondarySession.ID, false)
				require.Equal(ts.T(), models.AAL1.String(), session.GetAAL())
				require.Nil(ts.T(), session.FactorID)

			}
		})
	}

}

func (ts *MFATestSuite) TestUnenrollUnverifiedFactor() {
	user, session := ts.setupUserAndSession()

	var secondarySession *models.Session
	factors, err := models.FindFactorsByUser(ts.API.db, user)
	require.NoError(ts.T(), err, "error finding factors")
	f := factors[0]
	secondarySession, err = models.NewSession()
	require.NoError(ts.T(), err, "Error creating test session")
	secondarySession.UserID = user.ID
	secondarySession.FactorID = &f.ID
	require.NoError(ts.T(), ts.API.db.Create(secondarySession), "Error saving test session")

	sharedSecret := ts.TestOTPKey.Secret()
	f.Secret = sharedSecret

	var buffer bytes.Buffer

	token, _, err := generateAccessToken(ts.API.db, user, &session.ID, &ts.Config.JWT)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"factor_id": f.ID,
	}))

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/factors/%s", f.ID), &buffer)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)
	_, err = models.FindFactorByFactorID(ts.API.db, f.ID)
	require.EqualError(ts.T(), err, models.FactorNotFoundError{}.Error())
	session, _ = models.FindSessionByID(ts.API.db, secondarySession.ID, false)
	require.Equal(ts.T(), models.AAL1.String(), session.GetAAL())
	require.Nil(ts.T(), session.FactorID)

}

// Integration Tests
func (ts *MFATestSuite) TestSessionsMaintainAALOnRefresh() {
	resp := performTestSignupAndVerify(ts, ts.TestEmail, ts.TestPassword)
	accessTokenResp := &AccessTokenResponse{}
	require.NoError(ts.T(), json.NewDecoder(resp.Body).Decode(&accessTokenResp))

	ts.Config.Security.RefreshTokenRotationEnabled = true
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
	resp := performTestSignupAndVerify(ts, ts.TestEmail, ts.TestPassword)
	accessTokenResp := &AccessTokenResponse{}
	require.NoError(ts.T(), json.NewDecoder(resp.Body).Decode(&accessTokenResp))

	ts.Config.Security.RefreshTokenRotationEnabled = true
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
	var buffer bytes.Buffer

	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"email":    email,
		"password": password,
	}))

	// Setup request
	req := httptest.NewRequest(http.MethodPost, "http://localhost/signup", &buffer)
	req.Header.Set("Content-Type", "application/json")
	ts.API.config.Mailer.Autoconfirm = true
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)
	data := AccessTokenResponse{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))
	return data
}

func performTestSignupAndVerify(ts *MFATestSuite, email, password string) *httptest.ResponseRecorder {

	signUpResp := signUp(ts, email, password)
	resp := performEnrollAndVerify(ts, signUpResp.User, signUpResp.Token)

	return resp

}

func performEnrollFlow(ts *MFATestSuite, token, friendlyName, factorType, issuer string, expectedCode int) *httptest.ResponseRecorder {
	var buffer bytes.Buffer
	w := httptest.NewRecorder()
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]string{"friendly_name": friendlyName, "factor_type": factorType, "issuer": issuer}))

	req := httptest.NewRequest(http.MethodPost, "http://localhost/factors/", &buffer)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), expectedCode, w.Code)
	return w

}
func performVerifyFlow(ts *MFATestSuite, challengeID, factorID uuid.UUID, token string, expectedCode int) *httptest.ResponseRecorder {
	var verifyBuffer bytes.Buffer
	y := httptest.NewRecorder()

	conn, err := pgx.Connect(context.Background(), ts.API.db.URL())
	require.NoError(ts.T(), err)

	defer conn.Close(context.Background())

	var totpSecret string
	err = conn.QueryRow(context.Background(), "select secret from mfa_factors where id=$1", factorID).Scan(&totpSecret)
	require.NoError(ts.T(), err)

	code, err := totp.GenerateCode(totpSecret, time.Now().UTC())
	require.NoError(ts.T(), err)

	require.NoError(ts.T(), json.NewEncoder(&verifyBuffer).Encode(map[string]interface{}{
		"challenge_id": challengeID,
		"code":         code,
	}))
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/factors/%s/verify", factorID), &verifyBuffer)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	ts.API.handler.ServeHTTP(y, req)
	require.Equal(ts.T(), http.StatusOK, y.Code)
	return y
}

func performEnrollAndVerify(ts *MFATestSuite, user *models.User, token string) *httptest.ResponseRecorder {
	w := performEnrollFlow(ts, token, "", models.TOTP, ts.TestDomain, http.StatusOK)
	enrollResp := EnrollFactorResponse{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&enrollResp))
	factorID := enrollResp.ID

	// Challenge
	var challengeBuffer bytes.Buffer
	w = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("http://localhost/factors/%s/challenge", factorID), &challengeBuffer)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")
	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)
	challengeResp := EnrollFactorResponse{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&challengeResp))
	challengeID := challengeResp.ID

	// Verify
	y := performVerifyFlow(ts, challengeID, factorID, token, http.StatusOK)

	return y
}
