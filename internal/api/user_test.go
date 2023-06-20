package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/gotrue/internal/conf"
	"github.com/supabase/gotrue/internal/models"
)

type UserTestSuite struct {
	suite.Suite
	API    *API
	Config *conf.GlobalConfiguration
}

func TestUser(t *testing.T) {
	api, config, err := setupAPIForTest()
	require.NoError(t, err)

	ts := &UserTestSuite{
		API:    api,
		Config: config,
	}
	defer api.db.Close()

	suite.Run(t, ts)
}

func (ts *UserTestSuite) SetupTest() {
	models.TruncateAll(ts.API.db)

	// Create user
	u, err := models.NewUser("123456789", "test@example.com", "password", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err, "Error creating test user model")
	require.NoError(ts.T(), ts.API.db.Create(u), "Error saving new test user")
}

func (ts *UserTestSuite) TestUserGet() {
	u, err := models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err, "Error finding user")
	var token string
	token, err = generateAccessToken(ts.API.db, u, nil, &ts.Config.JWT)

	require.NoError(ts.T(), err, "Error generating access token")

	req := httptest.NewRequest(http.MethodGet, "http://localhost/user", nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)
}

func (ts *UserTestSuite) TestUserUpdateEmail() {
	cases := []struct {
		desc                       string
		userData                   map[string]string
		isSecureEmailChangeEnabled bool
		expectedCode               int
	}{
		{
			desc: "User doesn't have an existing email",
			userData: map[string]string{
				"email": "",
				"phone": "",
			},
			isSecureEmailChangeEnabled: false,
			expectedCode:               http.StatusOK,
		},
		{
			desc: "User doesn't have an existing email and double email confirmation required",
			userData: map[string]string{
				"email": "",
				"phone": "234567890",
			},
			isSecureEmailChangeEnabled: true,
			expectedCode:               http.StatusOK,
		},
		{
			desc: "User has an existing email",
			userData: map[string]string{
				"email": "foo@example.com",
				"phone": "",
			},
			isSecureEmailChangeEnabled: false,
			expectedCode:               http.StatusOK,
		},
		{
			desc: "User has an existing email and double email confirmation required",
			userData: map[string]string{
				"email": "bar@example.com",
				"phone": "",
			},
			isSecureEmailChangeEnabled: true,
			expectedCode:               http.StatusOK,
		},
	}

	for _, c := range cases {
		ts.Run(c.desc, func() {
			u, err := models.NewUser("", "", "", ts.Config.JWT.Aud, nil)
			require.NoError(ts.T(), err, "Error creating test user model")
			require.NoError(ts.T(), u.SetEmail(ts.API.db, c.userData["email"]), "Error setting user email")
			require.NoError(ts.T(), u.SetPhone(ts.API.db, c.userData["phone"]), "Error setting user phone")
			require.NoError(ts.T(), ts.API.db.Create(u), "Error saving test user")

			var token string
			token, err = generateAccessToken(ts.API.db, u, nil, &ts.Config.JWT)

			require.NoError(ts.T(), err, "Error generating access token")

			var buffer bytes.Buffer
			require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
				"email": "new@example.com",
			}))
			req := httptest.NewRequest(http.MethodPut, "http://localhost/user", &buffer)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

			w := httptest.NewRecorder()
			ts.Config.Mailer.SecureEmailChangeEnabled = c.isSecureEmailChangeEnabled
			ts.API.handler.ServeHTTP(w, req)
			require.Equal(ts.T(), c.expectedCode, w.Code)

			// remove user after each case
			require.NoError(ts.T(), ts.API.db.Destroy(u))
		})
	}

}
func (ts *UserTestSuite) TestUserUpdatePhoneAutoconfirmEnabled() {
	u, err := models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)

	existingUser, err := models.NewUser("22222222", "", "", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(existingUser))

	cases := []struct {
		desc         string
		userData     map[string]string
		expectedCode int
	}{
		{
			desc: "New phone number is the same as current phone number",
			userData: map[string]string{
				"phone": "123456789",
			},
			expectedCode: http.StatusOK,
		},
		{
			desc: "New phone number exists already",
			userData: map[string]string{
				"phone": "22222222",
			},
			expectedCode: http.StatusUnprocessableEntity,
		},
		{
			desc: "New phone number is different from current phone number",
			userData: map[string]string{
				"phone": "234567890",
			},
			expectedCode: http.StatusOK,
		},
	}

	ts.Config.Sms.Autoconfirm = true

	for _, c := range cases {
		ts.Run(c.desc, func() {
			var token string
			token, err = generateAccessToken(ts.API.db, u, nil, &ts.Config.JWT)
			require.NoError(ts.T(), err, "Error generating access token")

			var buffer bytes.Buffer
			require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
				"phone": c.userData["phone"],
			}))
			req := httptest.NewRequest(http.MethodPut, "http://localhost/user", &buffer)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

			w := httptest.NewRecorder()
			ts.API.handler.ServeHTTP(w, req)
			require.Equal(ts.T(), c.expectedCode, w.Code)
		})
	}

}

func (ts *UserTestSuite) TestUserUpdatePassword() {
	u, err := models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)

	type expected struct {
		code            int
		isAuthenticated bool
	}

	var cases = []struct {
		desc                    string
		newPassword             string
		nonce                   string
		requireReauthentication bool
		expected                expected
	}{
		{
			desc:                    "Valid password length",
			newPassword:             "newpassword",
			nonce:                   "",
			requireReauthentication: false,
			expected:                expected{code: http.StatusOK, isAuthenticated: true},
		},
		{
			desc:                    "Invalid password length",
			newPassword:             "",
			nonce:                   "",
			requireReauthentication: false,
			expected:                expected{code: http.StatusUnprocessableEntity, isAuthenticated: false},
		},
		{
			desc:                    "No reauthentication provided",
			newPassword:             "newpassword123",
			nonce:                   "",
			requireReauthentication: true,
			expected:                expected{code: http.StatusUnauthorized, isAuthenticated: false},
		},
		{
			desc:                    "Invalid nonce",
			newPassword:             "newpassword123",
			nonce:                   "123456",
			requireReauthentication: true,
			expected:                expected{code: http.StatusBadRequest, isAuthenticated: false},
		},
	}

	for _, c := range cases {
		ts.Run(c.desc, func() {
			ts.Config.Security.UpdatePasswordRequireReauthentication = c.requireReauthentication
			var buffer bytes.Buffer
			require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]string{"password": c.newPassword, "nonce": c.nonce}))

			req := httptest.NewRequest(http.MethodPut, "http://localhost/user", &buffer)
			req.Header.Set("Content-Type", "application/json")

			var token string
			token, err = generateAccessToken(ts.API.db, u, nil, &ts.Config.JWT)
			require.NoError(ts.T(), err)
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

			// Setup response recorder
			w := httptest.NewRecorder()
			ts.API.handler.ServeHTTP(w, req)
			require.Equal(ts.T(), c.expected.code, w.Code)

			// Request body
			u, err = models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
			require.NoError(ts.T(), err)

			require.Equal(ts.T(), c.expected.isAuthenticated, u.Authenticate(c.newPassword))
		})
	}
}

func (ts *UserTestSuite) TestUserUpdatePasswordReauthentication() {
	ts.Config.Security.UpdatePasswordRequireReauthentication = true

	u, err := models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)

	// Confirm the test user
	now := time.Now()
	u.EmailConfirmedAt = &now
	require.NoError(ts.T(), ts.API.db.Update(u), "Error updating new test user")

	var token string
	token, err = generateAccessToken(ts.API.db, u, nil, &ts.Config.JWT)
	require.NoError(ts.T(), err)

	// request for reauthentication nonce
	req := httptest.NewRequest(http.MethodGet, "http://localhost/reauthenticate", nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), w.Code, http.StatusOK)

	u, err = models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), u.ReauthenticationToken)
	require.NotEmpty(ts.T(), u.ReauthenticationSentAt)

	// update reauthentication token to a known token
	u.ReauthenticationToken = fmt.Sprintf("%x", sha256.Sum224([]byte(u.GetEmail()+"123456")))
	require.NoError(ts.T(), ts.API.db.Update(u))

	// update password with reauthentication token
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"password": "newpass",
		"nonce":    "123456",
	}))

	req = httptest.NewRequest(http.MethodPut, "http://localhost/user", &buffer)
	req.Header.Set("Content-Type", "application/json")

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), w.Code, http.StatusOK)

	// Request body
	u, err = models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)

	require.True(ts.T(), u.Authenticate("newpass"))
	require.Empty(ts.T(), u.ReauthenticationToken)
	require.NotEmpty(ts.T(), u.ReauthenticationSentAt)
}

func (ts *UserTestSuite) TestUserUpdatePasswordLogoutOtherSessions() {
	ts.Config.Security.UpdatePasswordRequireReauthentication = false
	u, err := models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)

	// Confirm the test user
	now := time.Now()
	u.EmailConfirmedAt = &now
	require.NoError(ts.T(), ts.API.db.Update(u), "Error updating new test user")

	// Login the test user to get first session
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"email":    u.GetEmail(),
		"password": "password",
	}))
	req := httptest.NewRequest(http.MethodPost, "http://localhost/token?grant_type=password", &buffer)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	session1 := AccessTokenResponse{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&session1))

	// Login test user to get second session
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"email":    u.GetEmail(),
		"password": "password",
	}))
	req = httptest.NewRequest(http.MethodPost, "http://localhost/token?grant_type=password", &buffer)
	req.Header.Set("Content-Type", "application/json")

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	session2 := AccessTokenResponse{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&session2))

	// Update user's password using first session
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"password": "newpass",
	}))

	req = httptest.NewRequest(http.MethodPut, "http://localhost/user", &buffer)
	req.Header.Set("Content-Type", "application/json")

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", session1.Token))

	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	// Attempt to refresh session1 should pass
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"refresh_token": session1.RefreshToken,
	}))

	req = httptest.NewRequest(http.MethodPost, "http://localhost/token?grant_type=refresh_token", &buffer)
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	// Attempt to refresh session2 should fail
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"refresh_token": session2.RefreshToken,
	}))

	req = httptest.NewRequest(http.MethodPost, "http://localhost/token?grant_type=refresh_token", &buffer)
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	require.NotEqual(ts.T(), http.StatusOK, w.Code)
}
