package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
)

type AnonymousTestSuite struct {
	suite.Suite
	API    *API
	Config *conf.GlobalConfiguration
}

func TestAnonymous(t *testing.T) {
	api, config, err := setupAPIForTest()
	require.NoError(t, err)

	ts := &AnonymousTestSuite{
		API:    api,
		Config: config,
	}
	defer api.db.Close()

	suite.Run(t, ts)
}

func (ts *AnonymousTestSuite) SetupTest() {
	models.TruncateAll(ts.API.db)

	// Create anonymous user
	params := &SignupParams{
		Aud:      ts.Config.JWT.Aud,
		Provider: "anonymous",
	}
	u, err := params.ToUserModel(false)
	require.NoError(ts.T(), err, "Error creating test user model")
	require.NoError(ts.T(), ts.API.db.Create(u), "Error saving new anonymous test user")
}

func (ts *AnonymousTestSuite) TestAnonymousLogins() {
	ts.Config.External.AnonymousUsers.Enabled = true
	// Request body
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"data": map[string]interface{}{
			"field": "foo",
		},
	}))

	req := httptest.NewRequest(http.MethodPost, "/signup", &buffer)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	data := &AccessTokenResponse{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))
	assert.NotEmpty(ts.T(), data.User.ID)
	assert.Equal(ts.T(), ts.Config.JWT.Aud, data.User.Aud)
	assert.Empty(ts.T(), data.User.GetEmail())
	assert.Empty(ts.T(), data.User.GetPhone())
	assert.True(ts.T(), data.User.IsAnonymous)
	assert.Equal(ts.T(), models.JSONMap(models.JSONMap{"field": "foo"}), data.User.UserMetaData)
}

func (ts *AnonymousTestSuite) TestConvertAnonymousUserToPermanent() {
	ts.Config.External.AnonymousUsers.Enabled = true
	// Request body
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{}))

	req := httptest.NewRequest(http.MethodPost, "/signup", &buffer)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	signupResponse := &AccessTokenResponse{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&signupResponse))

	// Add email to anonymous user
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"email": "test@example.com",
	}))

	req = httptest.NewRequest(http.MethodPut, "/user", &buffer)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", signupResponse.Token))

	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	// Check if anonymous user is still anonymous
	user, err := models.FindUserByID(ts.API.db, signupResponse.User.ID)
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), user)
	require.True(ts.T(), user.IsAnonymous)

	// Verify email change
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"token_hash": user.EmailChangeTokenNew,
		"type":       "email_change",
	}))

	req = httptest.NewRequest(http.MethodPost, "/verify", &buffer)
	req.Header.Set("Content-Type", "application/json")

	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	data := &AccessTokenResponse{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))

	// User is a permanent user and not anonymous anymore
	assert.Equal(ts.T(), signupResponse.User.ID, data.User.ID)
	assert.Equal(ts.T(), ts.Config.JWT.Aud, data.User.Aud)
	assert.Equal(ts.T(), "test@example.com", data.User.GetEmail())
	assert.Equal(ts.T(), models.JSONMap(models.JSONMap{"provider": "email", "providers": []interface{}{"email"}}), data.User.AppMetaData)
	assert.False(ts.T(), data.User.IsAnonymous)
	assert.NotEmpty(ts.T(), data.User.EmailConfirmedAt)

	// User should have an email identity
	assert.Len(ts.T(), data.User.Identities, 1)
}

func (ts *AnonymousTestSuite) TestRateLimitAnonymousSignups() {
	var buffer bytes.Buffer
	ts.Config.External.AnonymousUsers.Enabled = true

	// It rate limits after 30 requests
	for i := 0; i < int(ts.Config.RateLimitAnonymousUsers); i++ {
		require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{}))
		req := httptest.NewRequest(http.MethodPost, "http://localhost/signup", &buffer)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("My-Custom-Header", "1.2.3.4")
		w := httptest.NewRecorder()
		ts.API.handler.ServeHTTP(w, req)
		assert.Equal(ts.T(), http.StatusOK, w.Code)
	}

	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{}))
	req := httptest.NewRequest(http.MethodPost, "http://localhost/signup", &buffer)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("My-Custom-Header", "1.2.3.4")
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	assert.Equal(ts.T(), http.StatusTooManyRequests, w.Code)

	// It ignores X-Forwarded-For by default
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{}))
	req.Header.Set("X-Forwarded-For", "1.1.1.1")
	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	assert.Equal(ts.T(), http.StatusTooManyRequests, w.Code)

	// It doesn't rate limit a new value for the limited header
	req.Header.Set("My-Custom-Header", "5.6.7.8")
	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	assert.Equal(ts.T(), http.StatusBadRequest, w.Code)
}
