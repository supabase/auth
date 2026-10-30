package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/crypto"
	"github.com/supabase/auth/internal/mailer"
	"github.com/supabase/auth/internal/mailer/mockclient"
	"github.com/supabase/auth/internal/models"
)

type UserTestSuite struct {
	suite.Suite
	API    *API
	Config *conf.GlobalConfiguration
	Mailer mailer.Mailer
}

func TestUser(t *testing.T) {
	mockMailer := &mockclient.MockMailer{}
	api, config, err := setupAPIForTest(WithMailer(mockMailer))
	require.NoError(t, err)

	ts := &UserTestSuite{
		API:    api,
		Config: config,
		Mailer: mockMailer,
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

func (ts *UserTestSuite) generateToken(user *models.User, sessionId *uuid.UUID) string {
	req := httptest.NewRequest(http.MethodPost, "/token?grant_type=password", nil)
	token, _, err := ts.API.generateAccessToken(req, ts.API.db, user, sessionId, models.PasswordGrant)
	require.NoError(ts.T(), err, "Error generating access token")
	return token
}

func (ts *UserTestSuite) generateAccessTokenAndSession(user *models.User) string {
	session, err := models.NewSession(user.ID, nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(session))

	req := httptest.NewRequest(http.MethodPost, "/token?grant_type=password", nil)
	token, _, err := ts.API.generateAccessToken(req, ts.API.db, user, &session.ID, models.PasswordGrant)
	require.NoError(ts.T(), err, "Error generating access token")
	return token
}

func (ts *UserTestSuite) TestUserGet() {
	u, err := models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err, "Error finding user")
	token := ts.generateAccessTokenAndSession(u)

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
		userData                   map[string]interface{}
		isSecureEmailChangeEnabled bool
		isMailerAutoconfirmEnabled bool
		expectedCode               int
	}{
		{
			desc: "User doesn't have an existing email",
			userData: map[string]interface{}{
				"email": "",
				"phone": "",
			},
			isSecureEmailChangeEnabled: false,
			isMailerAutoconfirmEnabled: false,
			expectedCode:               http.StatusOK,
		},
		{
			desc: "User doesn't have an existing email and double email confirmation required",
			userData: map[string]interface{}{
				"email": "",
				"phone": "234567890",
			},
			isSecureEmailChangeEnabled: true,
			isMailerAutoconfirmEnabled: false,
			expectedCode:               http.StatusOK,
		},
		{
			desc: "User has an existing email",
			userData: map[string]interface{}{
				"email": "foo@example.com",
				"phone": "",
			},
			isSecureEmailChangeEnabled: false,
			isMailerAutoconfirmEnabled: false,
			expectedCode:               http.StatusOK,
		},
		{
			desc: "User has an existing email and double email confirmation required",
			userData: map[string]interface{}{
				"email": "bar@example.com",
				"phone": "",
			},
			isSecureEmailChangeEnabled: true,
			isMailerAutoconfirmEnabled: false,
			expectedCode:               http.StatusOK,
		},
		{
			desc: "Update email with mailer autoconfirm enabled",
			userData: map[string]interface{}{
				"email": "bar@example.com",
				"phone": "",
			},
			isSecureEmailChangeEnabled: true,
			isMailerAutoconfirmEnabled: true,
			expectedCode:               http.StatusOK,
		},
		{
			desc: "Update email with mailer autoconfirm enabled and anonymous user",
			userData: map[string]interface{}{
				"email":        "bar@example.com",
				"phone":        "",
				"is_anonymous": true,
			},
			isSecureEmailChangeEnabled: true,
			isMailerAutoconfirmEnabled: true,
			expectedCode:               http.StatusOK,
		},
	}

	for _, c := range cases {
		ts.Run(c.desc, func() {
			u, err := models.NewUser("", "", "", ts.Config.JWT.Aud, nil)
			require.NoError(ts.T(), err, "Error creating test user model")
			require.NoError(ts.T(), u.SetEmail(ts.API.db, c.userData["email"].(string)), "Error setting user email")
			require.NoError(ts.T(), u.SetPhone(ts.API.db, c.userData["phone"].(string)), "Error setting user phone")
			if isAnonymous, ok := c.userData["is_anonymous"]; ok {
				u.IsAnonymous = isAnonymous.(bool)
			}
			require.NoError(ts.T(), ts.API.db.Create(u), "Error saving test user")

			token := ts.generateAccessTokenAndSession(u)

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
			ts.Config.Mailer.Autoconfirm = c.isMailerAutoconfirmEnabled
			ts.API.handler.ServeHTTP(w, req)
			require.Equal(ts.T(), c.expectedCode, w.Code)

			var data models.User
			require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))

			if c.isMailerAutoconfirmEnabled && u.IsAnonymous {
				require.Empty(ts.T(), data.EmailChange)
				require.Equal(ts.T(), "new@example.com", data.GetEmail())
				require.Len(ts.T(), data.Identities, 1)
			} else {
				require.Equal(ts.T(), "new@example.com", data.EmailChange)
				require.Len(ts.T(), data.Identities, 0)
			}

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
			token := ts.generateAccessTokenAndSession(u)
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

			if c.expectedCode == http.StatusOK {
				// check that the user response returned contains the updated phone field
				data := &models.User{}
				require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))
				require.Equal(ts.T(), data.GetPhone(), c.userData["phone"])
			}
		})
	}

}

func (ts *UserTestSuite) TestUserUpdatePassword() {
	u, err := models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)

	r, err := models.GrantAuthenticatedUser(ts.API.db, u, models.GrantParams{})
	require.NoError(ts.T(), err)

	r2, err := models.GrantAuthenticatedUser(ts.API.db, u, models.GrantParams{})
	require.NoError(ts.T(), err)

	// create a session and modify it's created_at time to simulate a session that is not recently logged in
	notRecentlyLoggedIn, err := models.FindSessionByID(ts.API.db, *r2.SessionId, true)
	require.NoError(ts.T(), err)

	// cannot use Update here because Update doesn't removes the created_at field
	require.NoError(ts.T(), ts.API.db.RawQuery(
		"update "+notRecentlyLoggedIn.TableName()+" set created_at = ? where id = ?",
		time.Now().Add(-24*time.Hour),
		notRecentlyLoggedIn.ID).Exec(),
	)

	type expected struct {
		code            int
		isAuthenticated bool
	}

	var cases = []struct {
		desc                    string
		newPassword             string
		currentPassword         string
		nonce                   string
		requireReauthentication bool
		requireCurrentPassword  bool
		sessionId               *uuid.UUID
		expected                expected
	}{
		{
			desc:                    "Need reauthentication because outside of recently logged in window",
			newPassword:             "newpassword123",
			nonce:                   "",
			requireReauthentication: true,
			sessionId:               &notRecentlyLoggedIn.ID,
			expected:                expected{code: http.StatusBadRequest, isAuthenticated: false},
		},
		{
			desc:                    "No nonce provided",
			newPassword:             "newpassword123",
			nonce:                   "",
			sessionId:               &notRecentlyLoggedIn.ID,
			requireReauthentication: true,
			expected:                expected{code: http.StatusBadRequest, isAuthenticated: false},
		},
		{
			desc:                    "Invalid nonce",
			newPassword:             "newpassword1234",
			nonce:                   "123456",
			sessionId:               &notRecentlyLoggedIn.ID,
			requireReauthentication: true,
			expected:                expected{code: http.StatusUnprocessableEntity, isAuthenticated: false},
		},
		{
			desc:                    "No need reauthentication because recently logged in",
			newPassword:             "newpassword123",
			nonce:                   "",
			requireReauthentication: true,
			sessionId:               r.SessionId,
			expected:                expected{code: http.StatusOK, isAuthenticated: true},
		},
		{
			desc:                    "Current password checked when require current password set",
			newPassword:             "updateToNewpassword123",
			currentPassword:         "newpassword123", // match to the test case above
			nonce:                   "",
			requireReauthentication: false,
			requireCurrentPassword:  true,
			sessionId:               r.SessionId,
			expected:                expected{code: http.StatusOK, isAuthenticated: true},
		},
		{
			desc:                    "Fails if current password incorrect when require current password set",
			newPassword:             "newpassword123",
			currentPassword:         "randompassword",
			nonce:                   "",
			requireReauthentication: false,
			requireCurrentPassword:  true,
			sessionId:               r.SessionId,
			expected:                expected{code: http.StatusBadRequest, isAuthenticated: false},
		},
		{
			desc:                    "Fails if current password not set when required",
			newPassword:             "newpassword123",
			nonce:                   "",
			requireReauthentication: false,
			requireCurrentPassword:  true,
			sessionId:               r.SessionId,
			expected:                expected{code: http.StatusBadRequest, isAuthenticated: false},
		},
	}

	for _, c := range cases {
		ts.Run(c.desc, func() {
			ts.Config.Security.UpdatePasswordRequireReauthentication = c.requireReauthentication
			ts.Config.Security.UpdatePasswordRequireCurrentPassword = c.requireCurrentPassword

			userUpdateBody := map[string]string{"password": c.newPassword, "nonce": c.nonce}
			if c.requireCurrentPassword {
				userUpdateBody["current_password"] = c.currentPassword
			}
			var buffer bytes.Buffer
			require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(userUpdateBody))

			req := httptest.NewRequest(http.MethodPut, "http://localhost/user", &buffer)
			req.Header.Set("Content-Type", "application/json")
			token := ts.generateToken(u, c.sessionId)

			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

			// Setup response recorder
			w := httptest.NewRecorder()
			ts.API.handler.ServeHTTP(w, req)
			require.Equal(ts.T(), c.expected.code, w.Code)

			// Request body
			u, err = models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
			require.NoError(ts.T(), err)

			isAuthenticated, _, err := u.Authenticate(context.Background(), ts.API.db, c.newPassword, ts.API.config.Security.DBEncryption.DecryptionKeys, ts.API.config.Security.DBEncryption.Encrypt, ts.API.config.Security.DBEncryption.EncryptionKeyID)
			require.NoError(ts.T(), err)

			require.Equal(ts.T(), c.expected.isAuthenticated, isAuthenticated)
		})
	}
}

func (ts *UserTestSuite) TestUserUpdatePasswordViaRecovery() {
	ts.Config.Security.UpdatePasswordRequireCurrentPassword = true
	ts.Config.SMTP.MaxFrequency = 60
	u, err := models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	u.RecoverySentAt = &time.Time{}
	require.NoError(ts.T(), ts.API.db.Update(u))

	type expected struct {
		code            int
		isAuthenticated bool
	}

	var cases = []struct {
		desc            string
		newPassword     string
		currentPassword string
		recoveryType    models.AuthenticationMethod
		expected        expected
	}{
		{
			desc:         "Current password not required in OTP recovery flow",
			newPassword:  "newpassword123",
			recoveryType: models.OTP,
			expected:     expected{code: http.StatusOK, isAuthenticated: true},
		},
		{
			desc:         "Current password not required in magiclink recovery flow",
			newPassword:  "newpassword456",
			recoveryType: models.MagicLink,
			expected:     expected{code: http.StatusOK, isAuthenticated: true},
		},
		{
			desc:         "Current password not required in PKCE recovery flow",
			newPassword:  "newpassword789",
			recoveryType: models.Recovery,
			expected:     expected{code: http.StatusOK, isAuthenticated: true},
		},
		{
			desc:         "Current password required for any other claim",
			newPassword:  "newpassword456",
			recoveryType: models.EmailChange,
			expected:     expected{code: http.StatusBadRequest, isAuthenticated: false},
		},
	}

	for _, c := range cases {
		ts.Run(c.desc, func() {
			require.NoError(ts.T(), models.ClearAllOneTimeTokensForUser(ts.API.db, u.ID))

			// Create a session
			session, err := models.NewSession(u.ID, nil)
			require.NoError(ts.T(), err)
			require.NoError(ts.T(), ts.API.db.Create(session))

			// Add AMR claim to session to simulate recovery flow
			require.NoError(ts.T(), models.AddClaimToSession(ts.API.db, session.ID, c.recoveryType))

			// Reload session with AMR claims
			session, err = models.FindSessionByID(ts.API.db, session.ID, true)
			require.NoError(ts.T(), err)
			require.NotEmpty(ts.T(), session.AMRClaims, "Session should have AMR claims")

			// Generate access token with the recovery authentication method
			req := httptest.NewRequest(http.MethodPut, "http://localhost/user", nil)
			token, _, err := ts.API.generateAccessToken(req, ts.API.db, u, &session.ID, c.recoveryType)
			require.NoError(ts.T(), err)

			// Update password without current password
			userUpdateBody := map[string]string{"password": c.newPassword}
			var buffer bytes.Buffer
			require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(userUpdateBody))

			req = httptest.NewRequest(http.MethodPut, "http://localhost/user", &buffer)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

			// Setup response recorder
			w := httptest.NewRecorder()
			ts.API.handler.ServeHTTP(w, req)
			require.Equal(ts.T(), c.expected.code, w.Code)

			// Verify password was updated
			u, err = models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
			require.NoError(ts.T(), err)

			isAuthenticated, _, err := u.Authenticate(context.Background(), ts.API.db, c.newPassword, ts.API.config.Security.DBEncryption.DecryptionKeys, ts.API.config.Security.DBEncryption.Encrypt, ts.API.config.Security.DBEncryption.EncryptionKeyID)
			require.NoError(ts.T(), err)

			require.Equal(ts.T(), c.expected.isAuthenticated, isAuthenticated)
		})
	}
}

func (ts *UserTestSuite) TestUserUpdatePasswordNoReauthenticationRequired() {
	ts.Config.Security.UpdatePasswordRequireCurrentPassword = false
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
			desc:                    "Invalid password length",
			newPassword:             "",
			nonce:                   "",
			requireReauthentication: false,
			expected:                expected{code: http.StatusUnprocessableEntity, isAuthenticated: false},
		},

		{
			desc:                    "Valid password length",
			newPassword:             "newpassword",
			nonce:                   "",
			requireReauthentication: false,
			expected:                expected{code: http.StatusOK, isAuthenticated: true},
		},
	}

	for _, c := range cases {
		ts.Run(c.desc, func() {
			ts.Config.Security.UpdatePasswordRequireReauthentication = c.requireReauthentication
			var buffer bytes.Buffer
			require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]string{"password": c.newPassword, "nonce": c.nonce}))

			req := httptest.NewRequest(http.MethodPut, "http://localhost/user", &buffer)
			req.Header.Set("Content-Type", "application/json")
			token := ts.generateAccessTokenAndSession(u)

			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

			// Setup response recorder
			w := httptest.NewRecorder()
			ts.API.handler.ServeHTTP(w, req)
			require.Equal(ts.T(), c.expected.code, w.Code)

			// Request body
			u, err = models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
			require.NoError(ts.T(), err)

			isAuthenticated, _, err := u.Authenticate(context.Background(), ts.API.db, c.newPassword, ts.API.config.Security.DBEncryption.DecryptionKeys, ts.API.config.Security.DBEncryption.Encrypt, ts.API.config.Security.DBEncryption.EncryptionKeyID)
			require.NoError(ts.T(), err)

			require.Equal(ts.T(), c.expected.isAuthenticated, isAuthenticated)
		})
	}
}

func (ts *UserTestSuite) TestUserUpdatePasswordReauthentication() {
	ts.Config.Security.UpdatePasswordRequireReauthentication = true
	ts.Config.Security.UpdatePasswordRequireCurrentPassword = false
	u, err := models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)

	// Confirm the test user
	now := time.Now()
	u.EmailConfirmedAt = &now
	require.NoError(ts.T(), ts.API.db.Update(u), "Error updating new test user")

	token := ts.generateAccessTokenAndSession(u)

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
	u.ReauthenticationToken = crypto.GenerateTokenHash(u.GetEmail(), "123456")
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

	isAuthenticated, _, err := u.Authenticate(context.Background(), ts.API.db, "newpass", ts.Config.Security.DBEncryption.DecryptionKeys, ts.Config.Security.DBEncryption.Encrypt, ts.Config.Security.DBEncryption.EncryptionKeyID)
	require.NoError(ts.T(), err)

	require.True(ts.T(), isAuthenticated)
	require.Empty(ts.T(), u.ReauthenticationToken)
	require.Nil(ts.T(), u.ReauthenticationSentAt)
}

func (ts *UserTestSuite) TestUserUpdatePasswordLogoutOtherSessions() {
	ts.Config.Security.UpdatePasswordRequireReauthentication = false
	ts.Config.Security.UpdatePasswordRequireCurrentPassword = false
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

func (ts *UserTestSuite) TestUserUpdatePasswordSendsNotificationEmail() {
	cases := []struct {
		desc                        string
		password                    string
		notificationEnabled         bool
		expectedNotificationsCalled int
	}{
		{
			desc:                        "Password change notification enabled",
			password:                    "newpassword123",
			notificationEnabled:         true,
			expectedNotificationsCalled: 1,
		},
		{
			desc:                        "Password change notification disabled",
			password:                    "differentpassword456",
			notificationEnabled:         false,
			expectedNotificationsCalled: 0,
		},
	}

	for _, c := range cases {
		ts.Run(c.desc, func() {
			ts.Config.Security.UpdatePasswordRequireReauthentication = false
			ts.Config.Security.UpdatePasswordRequireCurrentPassword = false
			ts.Config.Mailer.Autoconfirm = false
			ts.Config.Mailer.Notifications.PasswordChangedEnabled = c.notificationEnabled

			u, err := models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
			require.NoError(ts.T(), err)

			// Confirm the test user
			now := time.Now()
			u.EmailConfirmedAt = &now
			require.NoError(ts.T(), ts.API.db.Update(u), "Error updating test user")

			// Get the mock mailer and reset it
			mockMailer, ok := ts.Mailer.(*mockclient.MockMailer)
			require.True(ts.T(), ok, "Mailer is not of type *MockMailer")
			mockMailer.Reset()

			token := ts.generateAccessTokenAndSession(u)

			// Update password
			var buffer bytes.Buffer
			require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
				"password": c.password,
			}))

			req := httptest.NewRequest(http.MethodPut, "http://localhost/user", &buffer)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

			w := httptest.NewRecorder()
			ts.API.handler.ServeHTTP(w, req)
			require.Equal(ts.T(), http.StatusOK, w.Code)

			// Verify password was updated
			u, err = models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
			require.NoError(ts.T(), err)

			// Assert that password change notification email was sent or not based on the instance's configuration
			require.Len(ts.T(), mockMailer.PasswordChangedMailCalls, c.expectedNotificationsCalled, fmt.Sprintf("Expected %d password change notification email(s) to be sent", c.expectedNotificationsCalled))
			if c.expectedNotificationsCalled > 0 {
				require.Equal(ts.T(), u.ID, mockMailer.PasswordChangedMailCalls[0].User.ID, "Email should be sent to the correct user")
			}
		})
	}
}

func (ts *UserTestSuite) putUserPassword(token string) *httptest.ResponseRecorder {
	var body bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&body).Encode(map[string]interface{}{
		"password": "newpassword123",
	}))

	req := httptest.NewRequest(http.MethodPut, "http://localhost/user", &body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	return w
}

func (ts *UserTestSuite) requireErrorCode(w *httptest.ResponseRecorder, status int, errorCode string) {
	require.Equal(ts.T(), status, w.Code, "unexpected status, body: %s", w.Body.String())

	data := make(map[string]interface{})
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))
	require.Equal(ts.T(), errorCode, data["error_code"])
}

// A customize_access_token hook may set session_id to a value that
// maybeLoadUserOrSession treats as "no session", since the token schema requires
// the claim to be present but does not constrain its value. The token Auth issues
// in that case must not be able to panic UserUpdate.
func (ts *UserTestSuite) TestUserUpdateWithSessionlessTokenFromHook() {
	cases := []struct {
		desc     string
		fnName   string
		sqlValue string
	}{
		{"blank session_id", "custom_access_token_blank_session", `'""'::jsonb`},
		{"nil uuid session_id", "custom_access_token_nil_session", `'"00000000-0000-0000-0000-000000000000"'::jsonb`},
	}

	for _, c := range cases {
		ts.T().Run(c.desc, func(t *testing.T) {
			require.NoError(t, models.TruncateAll(ts.API.db))

			u, err := models.NewUser("", "sessionless@example.com", "password", ts.Config.JWT.Aud, nil)
			require.NoError(t, err)
			now := time.Now()
			u.EmailConfirmedAt = &now
			require.NoError(t, ts.API.db.Create(u))

			refreshToken, err := models.GrantAuthenticatedUser(ts.API.db, u, models.GrantParams{})
			require.NoError(t, err)

			require.NoError(t, ts.API.db.RawQuery(fmt.Sprintf(`create or replace function %s(input jsonb) returns jsonb as $$
declare result jsonb;
begin
  input := jsonb_set(input, '{claims,session_id}', %s, true);
  result := jsonb_build_object('claims', input->'claims');
  return result;
end; $$ language plpgsql;`, c.fnName, c.sqlValue)).Exec())

			ts.Config.Hook.CustomAccessToken.Enabled = true
			ts.Config.Hook.CustomAccessToken.URI = "pg-functions://postgres/auth/" + c.fnName
			require.NoError(t, ts.Config.Hook.CustomAccessToken.PopulateExtensibilityPoint())

			ts.Config.Security.UpdatePasswordRequireCurrentPassword = true
			ts.Config.Security.UpdatePasswordRequireReauthentication = false

			defer func() {
				ts.Config.Hook.CustomAccessToken.Enabled = false
				ts.Config.Security.UpdatePasswordRequireCurrentPassword = false
				_ = ts.API.db.RawQuery("drop function if exists " + c.fnName).Exec()
			}()

			var buf bytes.Buffer
			require.NoError(t, json.NewEncoder(&buf).Encode(map[string]interface{}{
				"refresh_token": refreshToken.Token,
			}))
			req := httptest.NewRequest(http.MethodPost, "http://localhost/token?grant_type=refresh_token", &buf)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			ts.API.handler.ServeHTTP(w, req)
			require.Equal(t, http.StatusOK, w.Code, "hook output should pass claim validation, body: %s", w.Body.String())

			var tokenResponse struct {
				AccessToken string `json:"access_token"`
			}
			require.NoError(t, json.NewDecoder(w.Body).Decode(&tokenResponse))

			parts := strings.Split(tokenResponse.AccessToken, ".")
			require.Len(t, parts, 3)
			payload, err := base64.RawURLEncoding.DecodeString(parts[1])
			require.NoError(t, err)
			issued := make(map[string]interface{})
			require.NoError(t, json.Unmarshal(payload, &issued))
			require.Equal(t, u.ID.String(), issued["sub"])

			ts.requireErrorCode(ts.putUserPassword(tokenResponse.AccessToken),
				http.StatusBadRequest, apierrors.ErrorCodeCurrentPasswordRequired)
		})
	}
}

// Asserting the specific 401 and 400 rather than just "not a 500" is deliberate:
// a guard that failed open would also stop the panic, but would let the password
// through with no AAL2 and no current password.
func (ts *UserTestSuite) TestUserUpdateNilSessionFailsClosed() {
	mintSessionless := func(userID uuid.UUID, sessionID string) string {
		token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, &AccessTokenClaims{
			RegisteredClaims: jwt.RegisteredClaims{Subject: userID.String()},
			Role:             "authenticated",
			SessionId:        sessionID,
		}).SignedString([]byte(ts.Config.JWT.Secret))
		require.NoError(ts.T(), err)
		return token
	}

	sessionIDs := []struct{ desc, value string }{
		{"no session_id claim", ""},
		{"nil uuid session_id", uuid.Nil.String()},
	}

	ts.T().Run("AAL2 check when MFA is enabled", func(t *testing.T) {
		require.NoError(t, models.TruncateAll(ts.API.db))

		u, err := models.NewUser("", "nilsession-aal@example.com", "password", ts.Config.JWT.Aud, nil)
		require.NoError(t, err)
		require.NoError(t, ts.API.db.Create(u))

		f := models.NewTOTPFactor(u, "test-factor")
		require.NoError(t, f.SetSecret("secretkey",
			ts.Config.Security.DBEncryption.Encrypt,
			ts.Config.Security.DBEncryption.EncryptionKeyID,
			ts.Config.Security.DBEncryption.EncryptionKey))
		require.NoError(t, ts.API.db.Create(f))
		require.NoError(t, f.UpdateStatus(ts.API.db, models.FactorStateVerified))

		for _, s := range sessionIDs {
			t.Run(s.desc, func(t *testing.T) {
				ts.requireErrorCode(ts.putUserPassword(mintSessionless(u.ID, s.value)),
					http.StatusUnauthorized, apierrors.ErrorCodeInsufficientAAL)
			})
		}
	})

	ts.T().Run("current password check without MFA", func(t *testing.T) {
		require.NoError(t, models.TruncateAll(ts.API.db))

		ts.Config.Security.UpdatePasswordRequireCurrentPassword = true
		ts.Config.Security.UpdatePasswordRequireReauthentication = false
		defer func() {
			ts.Config.Security.UpdatePasswordRequireCurrentPassword = false
		}()

		u, err := models.NewUser("", "nilsession-password@example.com", "password", ts.Config.JWT.Aud, nil)
		require.NoError(t, err)
		require.NoError(t, ts.API.db.Create(u))

		for _, s := range sessionIDs {
			t.Run(s.desc, func(t *testing.T) {
				ts.requireErrorCode(ts.putUserPassword(mintSessionless(u.ID, s.value)),
					http.StatusBadRequest, apierrors.ErrorCodeCurrentPasswordRequired)
			})
		}
	})
}
