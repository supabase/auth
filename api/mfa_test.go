package api

import (
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
	API        *API
	Config     *conf.Configuration
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

	// Create user
	u, err := models.NewUser(ts.instanceID, "123456789", "test@example.com", "password", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err, "Error creating test user model")
	require.NoError(ts.T(), ts.API.db.Create(u), "Error saving new test user")
}

func (ts *MFATestSuite) TestMFAEnable() {
	u, err := models.FindUserByEmailAndAudience(ts.API.db, ts.instanceID, "test@example.com", ts.Config.JWT.Aud)
	token, err := generateAccessToken(u, time.Second*time.Duration(ts.Config.JWT.Exp), ts.Config.JWT.Secret)
	require.NoError(ts.T(), err)

	req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("http://localhost/mfa/%s/enable", u.ID), nil)
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

	req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("http://localhost/mfa/%s/disable", u.ID), nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), w.Code, http.StatusOK)

	u, err = models.FindUserByEmailAndAudience(ts.API.db, ts.instanceID, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	require.False(ts.T(), u.MFAEnabled)
}

func (ts *MFATestSuite) TestMFARecoveryCodeGeneration() {
	const expectedNumOfRecoveryCodes = 8

	user, err := models.FindUserByEmailAndAudience(ts.API.db, ts.instanceID, "test@example.com", ts.Config.JWT.Aud)
	ts.Require().NoError(err)
	require.NoError(ts.T(), user.EnableMFA(ts.API.db))

	token, err := generateAccessToken(user, time.Second*time.Duration(ts.Config.JWT.Exp), ts.Config.JWT.Secret)
	require.NoError(ts.T(), err)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/mfa/%s/generate_recovery_codes", user.ID), nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	data := make(map[string]interface{})
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))

	recoveryCodes := data["recovery_codes"].([]interface{})
	require.Equal(ts.T(), expectedNumOfRecoveryCodes, len(recoveryCodes))
}

func (ts *MFATestSuite) TestEnrollFactor() {
	// var cases = []struct {
	// 	desc                    string
	// 	newPassword             string
	// 	nonce                   string
	// 	requireReauthentication bool
	// 	expected                expected
	// }{
	// 	{
	// 		"Valid password length",
	// 		"newpassword",
	// 		"",
	// 		false,
	// 		expected{code: http.StatusOK, isAuthenticated: true},
	// 	},
	// 	{
	// 		"Invalid password length",
	// 		"",
	// 		"",
	// 		false,
	// 		expected{code: http.StatusUnprocessableEntity, isAuthenticated: false},
	// 	},
	// 	{
	// 		"No reauthentication provided",
	// 		"newpassword123",
	// 		"",
	// 		true,
	// 		expected{code: http.StatusUnauthorized, isAuthenticated: false},
	// 	},
	// 	{
	// 		"Invalid nonce",
	// 		"newpassword123",
	// 		"123456",
	// 		true,
	// 		expected{code: http.StatusBadRequest, isAuthenticated: false},
	// 	},
	// }
	// Check the return type, QR Code representation should be accurate
	//
	// for _, c := range cases {
	// 	ts.Run(c.desc, func() {
	// 		ts.Config.Security.UpdatePasswordRequireReauthentication = c.requireReauthentication
	// 		var buffer bytes.Buffer
	// 		require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]string{"password": c.newPassword, "nonce": c.nonce}))

	// 		req := httptest.NewRequest(http.MethodPut, "http://localhost/user", &buffer)
	// 		req.Header.Set("Content-Type", "application/json")

	// 		token, err := generateAccessToken(u, time.Second*time.Duration(ts.Config.JWT.Exp), ts.Config.JWT.Secret)
	// 		require.NoError(ts.T(), err)
	// 		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	// 		// Setup response recorder
	// 		w := httptest.NewRecorder()
	// 		ts.API.handler.ServeHTTP(w, req)
	// 		require.Equal(ts.T(), c.expected.code, w.Code)

	// 		// Request body
	// 		u, err = models.FindUserByEmailAndAudience(ts.API.db, ts.instanceID, "test@example.com", ts.Config.JWT.Aud)
	// 		require.NoError(ts.T(), err)

	// 		require.Equal(ts.T(), c.expected.isAuthenticated, u.Authenticate(c.newPassword))
	// 	})
	// }
	user, err := models.FindUserByEmailAndAudience(ts.API.db, ts.instanceID, "test@example.com", ts.Config.JWT.Aud)
	ts.Require().NoError(err)
	require.NoError(ts.T(), user.EnableMFA(ts.API.db))

	token, err := generateAccessToken(user, time.Second*time.Duration(ts.Config.JWT.Exp), ts.Config.JWT.Secret)
	require.NoError(ts.T(), err)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/mfa/%s/enroll_factor", user.ID), nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)
}
