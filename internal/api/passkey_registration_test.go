package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/models"
)

// TestRegisterPasskeyHappyPath tests the full happy path: get registration options, simulate
// an authenticator creating a credential, and verify the registration.
func (ts *PasskeyTestSuite) TestRegisterPasskeyHappyPath() {
	token := ts.generateToken(ts.TestUser, &ts.TestSession.ID)

	// Step 1: Get registration options
	w := ts.makeAuthenticatedRequest(http.MethodPost, "http://localhost/passkeys/registration/options", token, nil)
	ts.Require().Equal(http.StatusOK, w.Code)

	var optionsResp PasskeyRegistrationOptionsResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&optionsResp))
	ts.Require().NotEmpty(optionsResp.ChallengeID)
	ts.Require().NotNil(optionsResp.Options)

	// Step 2: Simulate the authenticator creating a credential
	authenticator := &virtualAuthenticator{
		rpID:   ts.Config.WebAuthn.RPID,
		origin: ts.Config.WebAuthn.RPOrigins[0],
	}

	credResp, err := authenticator.createCredential(optionsResp.Options)
	require.NoError(ts.T(), err)

	// Step 3: Verify the registration
	w = ts.makeAuthenticatedRequest(http.MethodPost, "http://localhost/passkeys/registration/verify", token, map[string]any{
		"challenge_id":        optionsResp.ChallengeID,
		"credential_response": json.RawMessage(credResp.JSON),
	})
	ts.Require().Equal(http.StatusOK, w.Code)

	var passkeyResp PasskeyMetadataResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&passkeyResp))

	ts.NotEmpty(passkeyResp.ID)
	ts.NotZero(passkeyResp.CreatedAt)

	// Step 4: Verify the credential was persisted
	passkeyID, err := uuid.FromString(passkeyResp.ID)
	require.NoError(ts.T(), err)
	cred, err := models.FindWebAuthnCredentialByID(ts.API.db, passkeyID)
	require.NoError(ts.T(), err)
	ts.Equal(ts.TestUser.ID, cred.UserID)
	ts.Equal("none", cred.AttestationType)
	ts.NotEmpty(cred.CredentialID)
	ts.NotEmpty(cred.PublicKey)

	// Step 5: Verify the challenge was consumed (deleted)
	challengeID, err := uuid.FromString(optionsResp.ChallengeID)
	require.NoError(ts.T(), err)
	_, err = models.FindWebAuthnChallengeByID(ts.API.db, challengeID)
	ts.True(models.IsNotFoundError(err))
}

// TestRegistrationOptionsSuccess tests that an authenticated user can get registration options.
func (ts *PasskeyTestSuite) TestRegistrationOptionsSuccess() {
	token := ts.generateToken(ts.TestUser, &ts.TestSession.ID)
	w := ts.makeAuthenticatedRequest(http.MethodPost, "http://localhost/passkeys/registration/options", token, nil)

	ts.Equal(http.StatusOK, w.Code)

	var resp PasskeyRegistrationOptionsResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&resp))

	ts.NotEmpty(resp.ChallengeID)
	ts.NotNil(resp.Options)
	ts.NotZero(resp.ExpiresAt)

	// Verify challenge was stored in database
	challengeID, err := uuid.FromString(resp.ChallengeID)
	require.NoError(ts.T(), err)
	challenge, err := models.FindWebAuthnChallengeByID(ts.API.db, challengeID)
	require.NoError(ts.T(), err)
	ts.Equal(models.WebAuthnChallengeTypeRegistration, challenge.ChallengeType)
	ts.Equal(ts.TestUser.ID, *challenge.UserID)
}

// TestRegistrationOptionsWithExistingPasskeys tests that existing credentials are excluded.
func (ts *PasskeyTestSuite) TestRegistrationOptionsWithExistingPasskeys() {
	// Create an existing passkey
	cred := &models.WebAuthnCredential{
		ID:              uuid.Must(uuid.NewV4()),
		UserID:          ts.TestUser.ID,
		CredentialID:    []byte("existing-cred-id"),
		PublicKey:       []byte("existing-pub-key"),
		AttestationType: "none",
	}
	require.NoError(ts.T(), ts.API.db.Create(cred))

	token := ts.generateToken(ts.TestUser, &ts.TestSession.ID)
	w := ts.makeAuthenticatedRequest(http.MethodPost, "http://localhost/passkeys/registration/options", token, nil)

	ts.Equal(http.StatusOK, w.Code)

	var resp PasskeyRegistrationOptionsResponse
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&resp))
	ts.NotEmpty(resp.ChallengeID)

	// The exclusion list should contain the existing credential
	ts.Require().NotNil(resp.Options)
	ts.Require().NotNil(resp.Options.Response.CredentialExcludeList)
	ts.Len(resp.Options.Response.CredentialExcludeList, 1)
}

// TestRegistrationOptionsTooManyPasskeys tests that the limit is enforced.
func (ts *PasskeyTestSuite) TestRegistrationOptionsTooManyPasskeys() {
	ts.Config.Passkey.MaxPasskeysPerUser = 1

	// Create one existing passkey to hit the limit
	cred := &models.WebAuthnCredential{
		ID:              uuid.Must(uuid.NewV4()),
		UserID:          ts.TestUser.ID,
		CredentialID:    []byte("cred-1"),
		PublicKey:       []byte("pk-1"),
		AttestationType: "none",
	}
	require.NoError(ts.T(), ts.API.db.Create(cred))

	token := ts.generateToken(ts.TestUser, &ts.TestSession.ID)
	w := ts.makeAuthenticatedRequest(http.MethodPost, "http://localhost/passkeys/registration/options", token, nil)

	ts.Equal(http.StatusUnprocessableEntity, w.Code)
	var errResp map[string]any
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&errResp))
	ts.Equal("too_many_passkeys", errResp["error_code"])
}

// TestRegistrationOptionsUnauthenticated tests that unauthenticated requests are rejected.
func (ts *PasskeyTestSuite) TestRegistrationOptionsUnauthenticated() {
	w := ts.makeRequest(http.MethodPost, "http://localhost/passkeys/registration/options", nil)
	ts.Equal(http.StatusUnauthorized, w.Code)
}

// TestRegistrationOptionsAnonymousUser tests that anonymous users are rejected.
func (ts *PasskeyTestSuite) TestRegistrationOptionsAnonymousUser() {
	ts.TestUser.IsAnonymous = true
	require.NoError(ts.T(), ts.API.db.Update(ts.TestUser))

	token := ts.generateToken(ts.TestUser, &ts.TestSession.ID)
	w := ts.makeAuthenticatedRequest(http.MethodPost, "http://localhost/passkeys/registration/options", token, nil)

	ts.Equal(http.StatusForbidden, w.Code)
}

// TestRegistrationOptionsSSOUser tests that SSO users are rejected.
func (ts *PasskeyTestSuite) TestRegistrationOptionsSSOUser() {
	ts.TestUser.IsSSOUser = true
	require.NoError(ts.T(), ts.API.db.Update(ts.TestUser))

	token := ts.generateToken(ts.TestUser, &ts.TestSession.ID)
	w := ts.makeAuthenticatedRequest(http.MethodPost, "http://localhost/passkeys/registration/options", token, nil)

	ts.Equal(http.StatusUnprocessableEntity, w.Code)
}

// TestRegistrationOptionsPasskeyDisabled tests that the feature gate works.
func (ts *PasskeyTestSuite) TestRegistrationOptionsPasskeyDisabled() {
	ts.Config.Passkey.Enabled = false

	token := ts.generateToken(ts.TestUser, &ts.TestSession.ID)
	w := ts.makeAuthenticatedRequest(http.MethodPost, "http://localhost/passkeys/registration/options", token, nil)

	ts.Equal(http.StatusNotFound, w.Code)
}

// TestRegisterVerifyChallengeNotFound tests that a missing challenge returns the correct error.
func (ts *PasskeyTestSuite) TestRegisterVerifyChallengeNotFound() {
	token := ts.generateToken(ts.TestUser, &ts.TestSession.ID)
	w := ts.makeAuthenticatedRequest(http.MethodPost, "http://localhost/passkeys/registration/verify", token, map[string]any{
		"challenge_id":        uuid.Must(uuid.NewV4()).String(),
		"credential_response": map[string]any{},
	})

	ts.Equal(http.StatusBadRequest, w.Code)
	var errResp map[string]any
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&errResp))
	ts.Equal("webauthn_challenge_not_found", errResp["error_code"])
}

// TestRegisterVerifyChallengeExpired tests that an expired challenge returns the correct error.
func (ts *PasskeyTestSuite) TestRegisterVerifyChallengeExpired() {
	challenge := models.NewWebAuthnChallenge(
		&ts.TestUser.ID,
		models.WebAuthnChallengeTypeRegistration,
		dummySessionData(),
		time.Now().Add(-1*time.Minute), // already expired
	)
	require.NoError(ts.T(), ts.API.db.Create(challenge))

	token := ts.generateToken(ts.TestUser, &ts.TestSession.ID)
	w := ts.makeAuthenticatedRequest(http.MethodPost, "http://localhost/passkeys/registration/verify", token, map[string]any{
		"challenge_id":        challenge.ID.String(),
		"credential_response": map[string]any{},
	})

	ts.Equal(http.StatusBadRequest, w.Code)
	var errResp map[string]any
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&errResp))
	ts.Equal("webauthn_challenge_expired", errResp["error_code"])
}

// TestRegisterVerifyWrongUser tests that a challenge belonging to a different user is rejected.
func (ts *PasskeyTestSuite) TestRegisterVerifyWrongUser() {
	otherUser, err := models.NewUser("", "other@example.com", "password", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(otherUser))

	challenge := models.NewWebAuthnChallenge(
		&otherUser.ID,
		models.WebAuthnChallengeTypeRegistration,
		dummySessionData(),
		time.Now().Add(5*time.Minute),
	)
	require.NoError(ts.T(), ts.API.db.Create(challenge))

	token := ts.generateToken(ts.TestUser, &ts.TestSession.ID)
	w := ts.makeAuthenticatedRequest(http.MethodPost, "http://localhost/passkeys/registration/verify", token, map[string]any{
		"challenge_id":        challenge.ID.String(),
		"credential_response": map[string]any{},
	})

	ts.Equal(http.StatusBadRequest, w.Code)
	var errResp map[string]any
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&errResp))
	ts.Equal("webauthn_challenge_not_found", errResp["error_code"])
}

// TestRegisterVerifyMissingFields tests validation of required fields.
func (ts *PasskeyTestSuite) TestRegisterVerifyMissingFields() {
	token := ts.generateToken(ts.TestUser, &ts.TestSession.ID)

	cases := []struct {
		desc string
		body map[string]any
	}{
		{
			desc: "missing challenge_id",
			body: map[string]any{
				"credential_response": map[string]any{},
			},
		},
		{
			desc: "missing credential_response",
			body: map[string]any{
				"challenge_id": uuid.Must(uuid.NewV4()).String(),
			},
		},
	}

	for _, c := range cases {
		ts.Run(c.desc, func() {
			w := ts.makeAuthenticatedRequest(http.MethodPost, "http://localhost/passkeys/registration/verify", token, c.body)
			ts.Equal(http.StatusBadRequest, w.Code)
		})
	}
}

// TestRegisterVerifyInvalidChallengeID tests that an invalid UUID is rejected.
func (ts *PasskeyTestSuite) TestRegisterVerifyInvalidChallengeID() {
	token := ts.generateToken(ts.TestUser, &ts.TestSession.ID)
	w := ts.makeAuthenticatedRequest(http.MethodPost, "http://localhost/passkeys/registration/verify", token, map[string]any{
		"challenge_id":        "not-a-uuid",
		"credential_response": map[string]any{},
	})

	ts.Equal(http.StatusBadRequest, w.Code)
}

// TestRegisterVerifyWrongChallengeType tests that a non-registration challenge is rejected.
func (ts *PasskeyTestSuite) TestRegisterVerifyWrongChallengeType() {
	challenge := models.NewWebAuthnChallenge(
		&ts.TestUser.ID,
		models.WebAuthnChallengeTypeAuthentication,
		dummySessionData(),
		time.Now().Add(5*time.Minute),
	)
	require.NoError(ts.T(), ts.API.db.Create(challenge))

	token := ts.generateToken(ts.TestUser, &ts.TestSession.ID)
	w := ts.makeAuthenticatedRequest(http.MethodPost, "http://localhost/passkeys/registration/verify", token, map[string]any{
		"challenge_id":        challenge.ID.String(),
		"credential_response": map[string]any{},
	})

	ts.Equal(http.StatusBadRequest, w.Code)
}

// TestRegisterVerifyUnauthenticated tests that unauthenticated requests are rejected.
func (ts *PasskeyTestSuite) TestRegisterVerifyUnauthenticated() {
	w := ts.makeRequest(http.MethodPost, "http://localhost/passkeys/registration/verify", map[string]any{
		"challenge_id":        uuid.Must(uuid.NewV4()).String(),
		"credential_response": map[string]any{},
	})
	ts.Equal(http.StatusUnauthorized, w.Code)
}

// TestRegisterVerifySSOUser tests that SSO users are rejected on verify too.
func (ts *PasskeyTestSuite) TestRegisterVerifySSOUser() {
	ts.TestUser.IsSSOUser = true
	require.NoError(ts.T(), ts.API.db.Update(ts.TestUser))

	token := ts.generateToken(ts.TestUser, &ts.TestSession.ID)
	w := ts.makeAuthenticatedRequest(http.MethodPost, "http://localhost/passkeys/registration/verify", token, map[string]any{
		"challenge_id":        uuid.Must(uuid.NewV4()).String(),
		"credential_response": map[string]any{},
	})

	ts.Equal(http.StatusUnprocessableEntity, w.Code)
}
