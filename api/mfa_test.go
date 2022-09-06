package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/netlify/gotrue/conf"
	"github.com/netlify/gotrue/models"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type MFATestSuite struct {
	suite.Suite
	API    *API
	Config *conf.GlobalConfiguration
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
	f, err := models.NewFactor(u, "testSimpleName", "testFactorID", "totp", models.FactorUnverifiedState, "secretkey")
	require.NoError(ts.T(), err, "Error creating test factor model")
	require.NoError(ts.T(), ts.API.db.Create(f), "Error saving new test factor")
}

func (ts *MFATestSuite) TestEnrollFactor() {
	// TODO(Joel): Check that only one factor can be enrolled
	var cases = []struct {
		desc         string
		FriendlyName string
		FactorType   string
		Issuer       string
		ExpectedCode int
	}{
		{
			"TOTP: No issuer",
			"john",
			"totp",
			"",
			http.StatusUnprocessableEntity,
		},
		{
			"Invalid factor type",
			"bob",
			"",
			"john.com",
			http.StatusUnprocessableEntity,
		},

		{
			"TOTP: Factor has friendly name",
			"bob",
			"totp",
			"supabase.com",
			http.StatusOK,
		},
		{
			"TOTP: Enrolling without friendly name",
			"",
			"totp",
			"supabase.com",
			http.StatusOK,
		},

	}
	for _, c := range cases {
		ts.Run(c.desc, func() {
			var buffer bytes.Buffer
			require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]string{"friendly_name": c.FriendlyName, "factor_type": c.FactorType, "issuer": c.Issuer}))
			user, err := models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
			ts.Require().NoError(err)

			token, err := generateAccessToken(user, "", time.Second*time.Duration(ts.Config.JWT.Exp), ts.Config.JWT.Secret, nil, "")
			require.NoError(ts.T(), err)

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/user/%s/factor/", user.ID), &buffer)
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
			req.Header.Set("Content-Type", "application/json")
			ts.API.handler.ServeHTTP(w, req)
			require.Equal(ts.T(), c.ExpectedCode, w.Code)

			factors, err := models.FindFactorsByUser(ts.API.db, user)
			ts.Require().NoError(err)
			latestFactor := factors[len(factors)-1]
			require.Equal(ts.T(), models.FactorUnverifiedState, latestFactor.Status)
			if c.FriendlyName != "" && c.ExpectedCode == http.StatusOK {
				require.Equal(ts.T(), c.FriendlyName, latestFactor.FriendlyName)
			}
		})
	}

}

func (ts *MFATestSuite) TestChallengeFactor() {
	u, err := models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)

	f, err := models.FindFactorByFactorID(ts.API.db, "testFactorID")
	require.NoError(ts.T(), err)

	token, err := generateAccessToken(u, "", time.Second*time.Duration(ts.Config.JWT.Exp), ts.Config.JWT.Secret, nil, "")
	require.NoError(ts.T(), err, "Error generating access token")

	var buffer bytes.Buffer
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("http://localhost/user/%s/factor/%s/challenge", u.ID, f.ID), &buffer)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)
}

// TODO: Check behavior that downgrades all other sessions
func (ts *MFATestSuite) TestMFAVerifyFactor() {
	cases := []struct {
		desc             string
		validChallenge   bool
		validCode        bool
		expectedHTTPCode int
	}{
		{
			"Invalid: Valid code and expired challenge",
			false,
			true,
			http.StatusUnauthorized,
		},
		{
			"Invalid: Invalid code and valid challenge ",
			true,
			false,
			http.StatusUnauthorized,
		},
		{
			"Valid /verify request",
			true,
			true,
			http.StatusOK,
		},
	}
	for _, v := range cases {
		ts.Run(v.desc, func() {
			u, err := models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
			emailValue, err := u.Email.Value()
			require.NoError(ts.T(), err)
			testEmail := emailValue.(string)
			testDomain := strings.Split(testEmail, "@")[1]
			// set factor secret
			key, err := totp.Generate(totp.GenerateOpts{
				Issuer:      testDomain,
				AccountName: testEmail,
			})
			sharedSecret := key.Secret()
			factors, err := models.FindFactorsByUser(ts.API.db, u)
			f := factors[0]
			f.SecretKey = sharedSecret
			require.NoError(ts.T(), err)
			require.NoError(ts.T(), ts.API.db.Update(f), "Error updating new test factor")

			// Make a challenge
			c, err := models.NewChallenge(f)
			require.NoError(ts.T(), err, "Error creating test Challenge model")
			require.NoError(ts.T(), ts.API.db.Create(c), "Error saving new test challenge")
			if !v.validChallenge {
				// Set challenge creation so that it has expired in present time.
				newCreatedAt := time.Now().UTC().Add(-1 * time.Second * time.Duration(ts.Config.MFA.ChallengeExpiryDuration+1))
				// created_at is managed by buffalo(ORM) needs to be raw query toe be updated
				err := ts.API.db.RawQuery("UPDATE auth.mfa_challenges SET created_at = ? WHERE factor_id = ?", newCreatedAt, f.ID).Exec()
				require.NoError(ts.T(), err, "Error updating new test challenge")
			}

			// Verify the user
			user, err := models.FindUserByEmailAndAudience(ts.API.db, testEmail, ts.Config.JWT.Aud)
			ts.Require().NoError(err)
			code, err := totp.GenerateCode(sharedSecret, time.Now().UTC())
			if !v.validCode {
				// Use an inaccurate time, resulting in an invalid code(usually)
				code, err = totp.GenerateCode(sharedSecret, time.Now().UTC().Add(-1*time.Minute*time.Duration(1)))
			}
			require.NoError(ts.T(), err)
			var buffer bytes.Buffer
			require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
				"challenge_id": c.ID,
				"code":         code,
			}))

			token, err := generateAccessToken(user, "", time.Second*time.Duration(ts.Config.JWT.Exp), ts.Config.JWT.Secret, nil, "")
			require.NoError(ts.T(), err)

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/user/%s/factor/%s/verify", user.ID, f.ID), &buffer)
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
			ts.API.handler.ServeHTTP(w, req)
			require.Equal(ts.T(), v.expectedHTTPCode, w.Code)

			// Check response
			data := VerifyFactorResponse{}
			if v.expectedHTTPCode == http.StatusOK {
				require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))
				require.Equal(ts.T(), data.Success, "true")
			}
			if !v.validChallenge {
				_, err := models.FindChallengeByChallengeID(ts.API.db, c.ID)
				require.EqualError(ts.T(), err, models.ChallengeNotFoundError{}.Error())
			}
			// Check the JWT to see if AAL is appropriate
		})
	}
}

func (ts *MFATestSuite) TestUnenrollFactor() {
	cases := []struct {
		desc             string
		IsFactorVerified bool
		ExpectedHTTPCode int
	}{
		{
			"Unverified Factor",
			false,
			http.StatusForbidden,
		},
		{
			"Verified Factor",
			true,
			http.StatusOK,
		},
	}
	for _, v := range cases {

		ts.Run(v.desc, func() {
			u, err := models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
			emailValue, err := u.Email.Value()
			require.NoError(ts.T(), err)
			testEmail := emailValue.(string)
			testDomain := strings.Split(testEmail, "@")[1]
			// Set factor secret
			key, err := totp.Generate(totp.GenerateOpts{
				Issuer:      testDomain,
				AccountName: testEmail,
			})
			sharedSecret := key.Secret()
			factors, err := models.FindFactorsByUser(ts.API.db, u)
			f := factors[0]
			f.SecretKey = sharedSecret
			if v.IsFactorVerified {
				err = f.UpdateStatus(ts.API.db, models.FactorVerifiedState)
				require.NoError(ts.T(), err)
			}

			require.NoError(ts.T(), ts.API.db.Update(f), "Error updating new test factor")

			var buffer bytes.Buffer

			token, err := generateAccessToken(u, "", time.Second*time.Duration(ts.Config.JWT.Exp), ts.Config.JWT.Secret, nil, "")
			require.NoError(ts.T(), err)

			code, err := totp.GenerateCode(sharedSecret, time.Now().UTC())
			require.NoError(ts.T(), err)
			require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
				"factor_id": f.ID,
				"code":      code,
			}))

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/user/%s/factor/%s/", u.ID, f.ID), &buffer)
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
			ts.API.handler.ServeHTTP(w, req)
			require.Equal(ts.T(), v.ExpectedHTTPCode, w.Code)
			if v.IsFactorVerified {
				_, err = models.FindFactorByFactorID(ts.API.db, f.ID)
				require.EqualError(ts.T(), err, models.FactorNotFoundError{}.Error())
			}
		})
	}

}
