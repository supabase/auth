package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/netlify/gotrue/conf"
	"github.com/netlify/gotrue/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type TokenTestSuite struct {
	suite.Suite
	API    *API
	Config *conf.GlobalConfiguration

	RefreshToken *models.RefreshToken
	User         *models.User
}

func TestToken(t *testing.T) {
	os.Setenv("GOTRUE_RATE_LIMIT_HEADER", "My-Custom-Header")
	api, config, err := setupAPIForTest()
	require.NoError(t, err)

	ts := &TokenTestSuite{
		API:    api,
		Config: config,
	}
	defer api.db.Close()

	suite.Run(t, ts)
}

func (ts *TokenTestSuite) SetupTest() {
	ts.RefreshToken = nil
	models.TruncateAll(ts.API.db)

	// Create user & refresh token
	u, err := models.NewUser("12345678", "test@example.com", "password", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err, "Error creating test user model")
	t := time.Now()
	u.EmailConfirmedAt = &t
	u.BannedUntil = nil
	require.NoError(ts.T(), ts.API.db.Create(u), "Error saving new test user")

	ts.User = u
	ts.RefreshToken, err = models.GrantAuthenticatedUser(ts.API.db, u, models.GrantParams{})
	require.NoError(ts.T(), err, "Error creating refresh token")
}

func (ts *TokenTestSuite) TestRateLimitTokenRefresh() {
	var buffer bytes.Buffer
	req := httptest.NewRequest(http.MethodPost, "http://localhost/token", &buffer)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("My-Custom-Header", "1.2.3.4")

	// It rate limits after 30 requests
	for i := 0; i < 30; i++ {
		w := httptest.NewRecorder()
		ts.API.handler.ServeHTTP(w, req)
		assert.Equal(ts.T(), http.StatusBadRequest, w.Code)
	}
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	assert.Equal(ts.T(), http.StatusTooManyRequests, w.Code)

	// It ignores X-Forwarded-For by default
	req.Header.Set("X-Forwarded-For", "1.1.1.1")
	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	assert.Equal(ts.T(), http.StatusTooManyRequests, w.Code)

	// It doesn't rate limit a new value for the limited header
	req = httptest.NewRequest(http.MethodPost, "http://localhost/token", &buffer)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("My-Custom-Header", "5.6.7.8")
	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	assert.Equal(ts.T(), http.StatusBadRequest, w.Code)
}

func (ts *TokenTestSuite) TestTokenPasswordGrantSuccess() {
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"email":    "test@example.com",
		"password": "password",
	}))

	req := httptest.NewRequest(http.MethodPost, "http://localhost/token?grant_type=password", &buffer)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	assert.Equal(ts.T(), http.StatusOK, w.Code)
}

func (ts *TokenTestSuite) TestTokenRefreshTokenGrantSuccess() {
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"refresh_token": ts.RefreshToken.Token,
	}))

	req := httptest.NewRequest(http.MethodPost, "http://localhost/token?grant_type=refresh_token", &buffer)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	assert.Equal(ts.T(), http.StatusOK, w.Code)
}

func (ts *TokenTestSuite) TestTokenPasswordGrantFailure() {
	u := ts.createBannedUser()

	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"email":    u.GetEmail(),
		"password": "password",
	}))

	req := httptest.NewRequest(http.MethodPost, "http://localhost/token?grant_type=password", &buffer)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	assert.Equal(ts.T(), http.StatusBadRequest, w.Code)
}

func (ts *TokenTestSuite) TestTokenRefreshTokenGrantFailure() {
	_ = ts.createBannedUser()

	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"refresh_token": ts.RefreshToken.Token,
	}))

	req := httptest.NewRequest(http.MethodPost, "http://localhost/token?grant_type=refresh_token", &buffer)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	assert.Equal(ts.T(), http.StatusBadRequest, w.Code)
}

func (ts *TokenTestSuite) TestTokenRefreshTokenRotation() {
	u, err := models.NewUser("", "foo@example.com", "password", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err, "Error creating test user model")
	t := time.Now()
	u.EmailConfirmedAt = &t
	require.NoError(ts.T(), ts.API.db.Create(u), "Error saving foo user")

	first, err := models.GrantAuthenticatedUser(ts.API.db, u, models.GrantParams{})
	require.NoError(ts.T(), err)
	second, err := models.GrantRefreshTokenSwap(&http.Request{}, ts.API.db, u, first)
	require.NoError(ts.T(), err)
	third, err := models.GrantRefreshTokenSwap(&http.Request{}, ts.API.db, u, second)
	require.NoError(ts.T(), err)

	cases := []struct {
		desc                        string
		refreshTokenRotationEnabled bool
		reuseInterval               int
		refreshToken                string
		expectedCode                int
		expectedBody                map[string]interface{}
	}{
		{
			desc:                        "Valid refresh within reuse interval",
			refreshTokenRotationEnabled: true,
			reuseInterval:               30,
			refreshToken:                second.Token,
			expectedCode:                http.StatusOK,
			expectedBody: map[string]interface{}{
				"refresh_token": third.Token,
			},
		},
		{
			desc:                        "Invalid refresh, first token is not the previous revoked token",
			refreshTokenRotationEnabled: true,
			reuseInterval:               0,
			refreshToken:                first.Token,
			expectedCode:                http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"error":             "invalid_grant",
				"error_description": "Invalid Refresh Token",
			},
		},
		{
			desc:                        "Invalid refresh, revoked third token",
			refreshTokenRotationEnabled: true,
			reuseInterval:               0,
			refreshToken:                second.Token,
			expectedCode:                http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"error":             "invalid_grant",
				"error_description": "Invalid Refresh Token",
			},
		},
		{
			desc:                        "Invalid refresh, third token revoked by previous case",
			refreshTokenRotationEnabled: true,
			reuseInterval:               30,
			refreshToken:                third.Token,
			expectedCode:                http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"error":             "invalid_grant",
				"error_description": "Invalid Refresh Token",
			},
		},
	}

	for _, c := range cases {
		ts.Run(c.desc, func() {
			ts.Config.Security.RefreshTokenRotationEnabled = c.refreshTokenRotationEnabled
			ts.Config.Security.RefreshTokenReuseInterval = c.reuseInterval
			var buffer bytes.Buffer
			require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
				"refresh_token": c.refreshToken,
			}))
			req := httptest.NewRequest(http.MethodPost, "http://localhost/token?grant_type=refresh_token", &buffer)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			ts.API.handler.ServeHTTP(w, req)
			assert.Equal(ts.T(), c.expectedCode, w.Code)

			data := make(map[string]interface{})
			require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))
			for k, v := range c.expectedBody {
				require.Equal(ts.T(), v, data[k])
			}
		})
	}
}

func (ts *TokenTestSuite) createBannedUser() *models.User {
	u, err := models.NewUser("", "banned@example.com", "password", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err, "Error creating test user model")
	t := time.Now()
	u.EmailConfirmedAt = &t
	t = t.Add(24 * time.Hour)
	u.BannedUntil = &t
	require.NoError(ts.T(), ts.API.db.Create(u), "Error saving new test banned user")

	ts.RefreshToken, err = models.GrantAuthenticatedUser(ts.API.db, u, models.GrantParams{})
	require.NoError(ts.T(), err, "Error creating refresh token")

	return u
}

func (ts *TokenTestSuite) TestTokenRefreshWithExpiredSession() {
	var err error

	now := time.Now().UTC().Add(-1 * time.Second)

	ts.RefreshToken, err = models.GrantAuthenticatedUser(ts.API.db, ts.User, models.GrantParams{
		SessionNotAfter: &now,
	})
	require.NoError(ts.T(), err, "Error creating refresh token")

	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"refresh_token": ts.RefreshToken.Token,
	}))

	req := httptest.NewRequest(http.MethodPost, "http://localhost/token?grant_type=refresh_token", &buffer)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	assert.Equal(ts.T(), http.StatusBadRequest, w.Code)
}

func (ts *TokenTestSuite) TestTokenRefreshWithUnexpiredSession() {
	var err error

	now := time.Now().UTC().Add(1 * time.Second)

	ts.RefreshToken, err = models.GrantAuthenticatedUser(ts.API.db, ts.User, models.GrantParams{
		SessionNotAfter: &now,
	})
	require.NoError(ts.T(), err, "Error creating refresh token")

	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"refresh_token": ts.RefreshToken.Token,
	}))

	req := httptest.NewRequest(http.MethodPost, "http://localhost/token?grant_type=refresh_token", &buffer)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	assert.Equal(ts.T(), http.StatusOK, w.Code)
}
