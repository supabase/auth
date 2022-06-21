package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/conf"
	"github.com/netlify/gotrue/models"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type MFATestSuite struct {
	suite.Suite
	API    *API
	Config *conf.Configuration

	instanceID uuid.UUID
}

func TestMFA(t *testing.T) {
	api, config, instanceID, err := setupAPIForTestForInstance()
	require.NoError(t, err)

	ts := &MFATestSuite{
		API:        api,
		Config:     config,
		instanceID: instanceID,
	}
	defer api.db.Close()

	suite.Run(t, ts)
}

func (ts *MFATestSuite) SetupTest() {
	models.TruncateAll(ts.API.db)
	u, err := models.NewUser(ts.instanceID, "123456789", "test@example.com", "password", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err, "Error creating test user model")
	require.NoError(ts.T(), ts.API.db.Create(u), "Error saving new test user")
	f, err := models.NewFactor(u, "testSimpleName", "testFactorID", "phone", "secretkey")
	require.NoError(ts.T(), err, "Error creating test factor model")
	require.NoError(ts.T(), ts.API.db.Create(f), "Error saving new test factor")
}

func (ts *MFATestSuite) TestMFAEnable() {
	u, err := models.FindUserByEmailAndAudience(ts.API.db, ts.instanceID, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), u.EnableMFA(ts.API.db))
	require.NoError(ts.T(), u.DisableMFA(ts.API.db))

	token, err := generateAccessToken(u, time.Second*time.Duration(ts.Config.JWT.Exp), ts.Config.JWT.Secret)
	require.NoError(ts.T(), err)

	req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("http://localhost/mfa/%s/enable_mfa", u.ID), nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), w.Code, http.StatusOK)

	u, err = models.FindUserByEmailAndAudience(ts.API.db, ts.instanceID, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	require.True(ts.T(), u.MFAEnabled)

}

func (ts *MFATestSuite) TestMFADisable() {
	u, err := models.FindUserByEmailAndAudience(ts.API.db, ts.instanceID, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), u.EnableMFA(ts.API.db))

	token, err := generateAccessToken(u, time.Second*time.Duration(ts.Config.JWT.Exp), ts.Config.JWT.Secret)
	require.NoError(ts.T(), err)

	req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("http://localhost/mfa/%s/disable_mfa", u.ID), nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), w.Code, http.StatusOK)

	u, err = models.FindUserByEmailAndAudience(ts.API.db, ts.instanceID, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	require.False(ts.T(), u.MFAEnabled)
}

func (ts *MFATestSuite) TestMFARecoveryCodeGeneration() {
	const EXPECTED_NUM_OF_RECOVERY_CODES = 8

	u, err := models.NewUser(ts.instanceID, "", "test1@example.com", "test", ts.Config.JWT.Aud, nil)
	u.MFAEnabled = true

	err = ts.API.db.Create(u)
	require.NoError(ts.T(), err)

	token, err := generateAccessToken(u, time.Second*time.Duration(ts.Config.JWT.Exp), ts.Config.JWT.Secret)
	require.NoError(ts.T(), err)

	user, err := models.FindUserByEmailAndAudience(ts.API.db, ts.instanceID, "test1@example.com", ts.Config.JWT.Aud)
	ts.Require().NoError(err)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/mfa/%s/generate_recovery_codes", user.ID), nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	ts.API.handler.ServeHTTP(w, req)

	data := make(map[string]interface{})

	require.Equal(ts.T(), http.StatusOK, w.Code)

	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))
	backupCodes := data["RecoveryCodes"].([]interface{})

	numCodes := len(backupCodes)
	require.Equal(ts.T(), EXPECTED_NUM_OF_RECOVERY_CODES, numCodes)
}

func (ts *MFATestSuite) TestChallengeFactor() {

	cases := []struct {
		desc         string
		id           string
		simpleName   string
		mfaEnabled   bool
		expectedCode int
	}{
		{
			"MFA Not Enabled",
			"",
			"",
			false,
			http.StatusForbidden,
		},
		{
			"Both Factor ID and Simple Name are present",
			"testFactorID",
			"testSimpleFactor",
			true,
			http.StatusUnprocessableEntity,
		},
		{
			"Only factor simple name",
			"",
			"testSimpleName",
			true,
			http.StatusOK,
		},
		{
			"Only factor ID",
			"testFactorID",
			"",
			true,
			http.StatusOK,
		},
		{
			"Both factor and simple name missing",
			"",
			"",
			true,
			http.StatusUnprocessableEntity,
		},
	}

	for _, c := range cases {
		ts.Run(c.desc, func() {
			u, err := models.FindUserByEmailAndAudience(ts.API.db, ts.instanceID, "test@example.com", ts.Config.JWT.Aud)
			require.NoError(ts.T(), err)

			if c.mfaEnabled {
				require.NoError(ts.T(), u.EnableMFA(ts.API.db), "Error setting MFA to disabled")
			}

			token, err := generateAccessToken(u, time.Second*time.Duration(ts.Config.JWT.Exp), ts.Config.JWT.Secret)
			require.NoError(ts.T(), err, "Error generating access token")

			var buffer bytes.Buffer
			require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
				"factor_id":          c.id,
				"factor_simple_name": c.simpleName,
			}))

			req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("http://localhost/mfa/%s/challenge_factor", u.ID), &buffer)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

			w := httptest.NewRecorder()
			ts.API.handler.ServeHTTP(w, req)
			require.Equal(ts.T(), c.expectedCode, w.Code)
		})
	}
}
