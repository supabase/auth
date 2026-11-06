package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
)

type RecoverTestSuite struct {
	suite.Suite
	API    *API
	Config *conf.GlobalConfiguration
}

func TestRecover(t *testing.T) {
	api, config, err := setupAPIForTest()
	require.NoError(t, err)

	ts := &RecoverTestSuite{
		API:    api,
		Config: config,
	}
	defer api.db.Close()

	suite.Run(t, ts)
}

func (ts *RecoverTestSuite) SetupTest() {
	models.TruncateAll(ts.API.db)

	// Create user
	u, err := models.NewUser("", "test@example.com", "password", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err, "Error creating test user model")
	require.NoError(ts.T(), ts.API.db.Create(u), "Error saving new test user")
}

func (ts *RecoverTestSuite) TestRecover_FirstRecovery() {
	u, err := models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	u.RecoverySentAt = &time.Time{}
	require.NoError(ts.T(), ts.API.db.Update(u))

	// Request body
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"email": "test@example.com",
	}))

	// Setup request
	req := httptest.NewRequest(http.MethodPost, "http://localhost/recover", &buffer)
	req.Header.Set("Content-Type", "application/json")

	// Setup response recorder
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	assert.Equal(ts.T(), http.StatusOK, w.Code)

	u, err = models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)

	assert.WithinDuration(ts.T(), time.Now(), *u.RecoverySentAt, 1*time.Second)
}

func (ts *RecoverTestSuite) TestRecover_NoEmailSent() {
	recoveryTime := time.Now().UTC().Add(-59 * time.Second)
	u, err := models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	u.RecoverySentAt = &recoveryTime
	require.NoError(ts.T(), ts.API.db.Update(u))

	// Request body
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"email": "test@example.com",
	}))

	// Setup request
	req := httptest.NewRequest(http.MethodPost, "http://localhost/recover", &buffer)
	req.Header.Set("Content-Type", "application/json")

	// Setup response recorder
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	assert.Equal(ts.T(), http.StatusTooManyRequests, w.Code)

	u, err = models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)

	// ensure it did not send a new email
	u1 := recoveryTime.Round(time.Second).Unix()
	u2 := u.RecoverySentAt.Round(time.Second).Unix()
	assert.Equal(ts.T(), u1, u2)
}

func (ts *RecoverTestSuite) TestRecover_NewEmailSent() {
	recoveryTime := time.Now().UTC().Add(-20 * time.Minute)
	u, err := models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	u.RecoverySentAt = &recoveryTime
	require.NoError(ts.T(), ts.API.db.Update(u))

	// Request body
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"email": "test@example.com",
	}))

	// Setup request
	req := httptest.NewRequest(http.MethodPost, "http://localhost/recover", &buffer)
	req.Header.Set("Content-Type", "application/json")

	// Setup response recorder
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	assert.Equal(ts.T(), http.StatusOK, w.Code)

	u, err = models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)

	// ensure it sent a new email
	assert.WithinDuration(ts.T(), time.Now(), *u.RecoverySentAt, 1*time.Second)
}

func (ts *RecoverTestSuite) TestRecover_NoSideChannelLeak() {
	email := "doesntexist@example.com"

	_, err := models.FindUserByEmailAndAudience(ts.API.db, email, ts.Config.JWT.Aud)
	require.True(ts.T(), models.IsNotFoundError(err), "User with email %s does exist", email)

	// Request body
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"email": email,
	}))

	// Setup request
	req := httptest.NewRequest(http.MethodPost, "http://localhost/recover", &buffer)
	req.Header.Set("Content-Type", "application/json")

	// Setup response recorder
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	assert.Equal(ts.T(), http.StatusOK, w.Code)
}

func (ts *RecoverTestSuite) TestRecover_BannedUser() {
	u, err := models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), u.Ban(ts.API.db, time.Hour))

	doRecover := func() *httptest.ResponseRecorder {
		var buffer bytes.Buffer
		require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
			"email": "test@example.com",
		}))
		req := httptest.NewRequest(http.MethodPost, "http://localhost/recover", &buffer)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		ts.API.handler.ServeHTTP(w, req)
		return w
	}

	w := doRecover()
	assert.Equal(ts.T(), http.StatusOK, w.Code)
	assert.JSONEq(ts.T(), "{}", w.Body.String())

	u, err = models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	assert.Empty(ts.T(), u.RecoveryToken)
	assert.Nil(ts.T(), u.RecoverySentAt)

	// once the ban has expired, the recovery email is sent again
	pastBan := time.Now().Add(-time.Hour)
	u.BannedUntil = &pastBan
	require.NoError(ts.T(), ts.API.db.UpdateOnly(u, "banned_until"))

	w = doRecover()
	assert.Equal(ts.T(), http.StatusOK, w.Code)

	u, err = models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	assert.NotEmpty(ts.T(), u.RecoveryToken)
	require.NotNil(ts.T(), u.RecoverySentAt)
	assert.WithinDuration(ts.T(), time.Now(), *u.RecoverySentAt, 1*time.Second)
}

func (ts *RecoverTestSuite) TestRecover_BannedUserMaxFrequency() {
	origFreq := ts.Config.SMTP.MaxFrequency
	ts.Config.SMTP.MaxFrequency = time.Minute
	defer func() { ts.Config.SMTP.MaxFrequency = origFreq }()

	u, err := models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	sentAt := time.Now().Add(-10 * time.Second)
	u.RecoverySentAt = &sentAt
	require.NoError(ts.T(), ts.API.db.UpdateOnly(u, "recovery_sent_at"))

	doRecover := func() int {
		var buffer bytes.Buffer
		require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{"email": "test@example.com"}))
		req := httptest.NewRequest(http.MethodPost, "http://localhost/recover", &buffer)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		ts.API.handler.ServeHTTP(w, req)
		return w.Code
	}

	// not banned: rate limited
	assert.Equal(ts.T(), http.StatusTooManyRequests, doRecover())

	// banned: indistinguishable from the not banned response
	require.NoError(ts.T(), u.Ban(ts.API.db, time.Hour))
	assert.Equal(ts.T(), http.StatusTooManyRequests, doRecover())

	// banned, but outside of the max frequency window: 200
	old := time.Now().Add(-2 * time.Minute)
	u.RecoverySentAt = &old
	require.NoError(ts.T(), ts.API.db.UpdateOnly(u, "recovery_sent_at"))
	assert.Equal(ts.T(), http.StatusOK, doRecover())
}
