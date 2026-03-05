package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
)

// PasskeyTestSuite is the shared test suite for all passkey flow tests.
// Flow-specific test methods live in their own files (passkey_register_test.go, etc.).
type PasskeyTestSuite struct {
	suite.Suite
	API         *API
	Config      *conf.GlobalConfiguration
	TestUser    *models.User
	TestSession *models.Session
}

func TestPasskey(t *testing.T) {
	api, config, err := setupAPIForTest()
	require.NoError(t, err)
	ts := &PasskeyTestSuite{
		API:    api,
		Config: config,
	}
	defer api.db.Close()
	suite.Run(t, ts)
}

func (ts *PasskeyTestSuite) SetupTest() {
	models.TruncateAll(ts.API.db)

	// Enable passkeys
	ts.Config.Passkey.Enabled = true
	ts.Config.Passkey.MaxPasskeysPerUser = 10
	ts.Config.WebAuthn = conf.WebAuthnConfiguration{
		RPID:                    "localhost",
		RPDisplayName:           "Test App",
		RPOrigins:               []string{"http://localhost:3000"},
		ChallengeExpiryDuration: 5 * time.Minute,
	}

	// Create test user
	u, err := models.NewUser("", "passkey@example.com", "password", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(u))

	// Create session
	s, err := models.NewSession(u.ID, nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(s))

	ts.TestUser = u
	ts.TestSession = s
}

// generateToken creates a JWT access token for the given user and session.
func (ts *PasskeyTestSuite) generateToken(user *models.User, sessionID *uuid.UUID) string {
	req := httptest.NewRequest(http.MethodPost, "/passkeys", nil)
	token, _, err := ts.API.generateAccessToken(req, ts.API.db, user, sessionID, models.PasswordGrant)
	require.NoError(ts.T(), err)

	return token
}

// makeAuthenticatedRequest sends an HTTP request with a Bearer token.
func (ts *PasskeyTestSuite) makeAuthenticatedRequest(method, path, token string, body any) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		require.NoError(ts.T(), json.NewEncoder(&buf).Encode(body))
	}

	w := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")
	ts.API.handler.ServeHTTP(w, req)

	return w
}

// makeRequest sends an unauthenticated HTTP request.
func (ts *PasskeyTestSuite) makeRequest(method, path string, body any) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		require.NoError(ts.T(), json.NewEncoder(&buf).Encode(body))
	}

	w := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	ts.API.handler.ServeHTTP(w, req)

	return w
}

// dummySessionData creates a minimal WebAuthnSessionData for test challenges.
func dummySessionData() *models.WebAuthnSessionData {
	return &models.WebAuthnSessionData{
		SessionData: &webauthn.SessionData{
			Challenge:        "dGVzdC1jaGFsbGVuZ2U",
			UserID:           []byte("test-user"),
			UserVerification: protocol.VerificationPreferred,
		},
	}
}
