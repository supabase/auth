package api

import (
	"bytes"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/conf"
	"github.com/netlify/gotrue/models"
	"github.com/pquerna/otp/totp"
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
	const EXPECTED_NUM_OF_RECOVERY_CODES = 8
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
	require.Equal(ts.T(), EXPECTED_NUM_OF_RECOVERY_CODES, len(recoveryCodes))
}

func (ts *MFATestSuite) TestMFAVerifyFactor() {
	u, err := models.NewUser(ts.instanceID, "1234567891", "test123@example.com", "password", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err, "Error creating test user model")
	require.NoError(ts.T(), ts.API.db.Create(u), "Error saving new test user")

	f, err := models.NewFactor(u, "testSimpleName", "testFactorID", "totp", "disabled", "secretkey")
	require.NoError(ts.T(), err, "Error creating test factor model")
	require.NoError(ts.T(), ts.API.db.Create(f), "Error saving new test factor")

	c, err := models.NewChallenge(f.ID)
	require.NoError(ts.T(), err, "Error creating test Challenge model")
	require.NoError(ts.T(), ts.API.db.Create(c), "Error saving new test challenge")
	// TOTP library takes in base32 string
	secret := base32.StdEncoding.EncodeToString([]byte(f.SecretKey))
	code, err := totp.GenerateCode(secret, time.Now().UTC())
	require.NoError(ts.T(), err)

	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"challenge_id": c.ID,
		"code":         code,
	}))
	user, err := models.FindUserByEmailAndAudience(ts.API.db, ts.instanceID, "test@example.com", ts.Config.JWT.Aud)
	ts.Require().NoError(err)
	require.NoError(ts.T(), user.EnableMFA(ts.API.db))

	token, err := generateAccessToken(user, time.Second*time.Duration(ts.Config.JWT.Exp), ts.Config.JWT.Secret)
	require.NoError(ts.T(), err)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/mfa/%s/verify", user.ID), &buffer)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	// data := make(map[string]interface{})
	// require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))
}
