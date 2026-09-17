package models

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/conf/confload"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/storage/test"
)

type SessionsTestSuite struct {
	suite.Suite
	db     *storage.Connection
	Config *conf.GlobalConfiguration
}

func (ts *SessionsTestSuite) SetupTest() {
	TruncateAll(ts.db)
	email := "test@example.com"
	user, err := NewUser("", email, "secret", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err)

	err = ts.db.Create(user)
	require.NoError(ts.T(), err)
}

func TestSession(t *testing.T) {
	globalConfig, err := confload.LoadGlobal(modelsTestConfig)
	require.NoError(t, err)
	conn, err := test.SetupDBConnection(globalConfig)
	require.NoError(t, err)
	ts := &SessionsTestSuite{
		db:     conn,
		Config: globalConfig,
	}
	defer ts.db.Close()
	suite.Run(t, ts)
}

func (ts *SessionsTestSuite) TestFindBySessionIDWithForUpdate() {
	u, err := FindUserByEmailAndAudience(ts.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	session, err := NewSession(u.ID, nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(session))

	found, err := FindSessionByID(ts.db, session.ID, true)
	require.NoError(ts.T(), err)

	require.Equal(ts.T(), session.ID, found.ID)
}

func (ts *SessionsTestSuite) TestInvalidateSessionsWithAALLessThan_PreservesOAuthSessions() {
	u, err := FindUserByEmailAndAudience(ts.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)

	// Standard AAL1 browser session
	browserSession, err := NewSession(u.ID, nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(browserSession))

	// OAuth client session (also AAL1, but has oauth_client_id set)
	clientName := "OAuth App"
	client := &OAuthServerClient{
		ID:                      uuid.Must(uuid.NewV4()),
		ClientName:              &clientName,
		RegistrationType:        "dynamic",
		ClientType:              OAuthServerClientTypeConfidential,
		ClientSecretHash:        "hash",
		RedirectURIs:            "https://example.com/callback",
		GrantTypes:              "authorization_code,refresh_token",
		TokenEndpointAuthMethod: TokenEndpointAuthMethodClientSecretBasic,
	}
	require.NoError(ts.T(), CreateOAuthServerClient(ts.db, client))

	oauthSession, err := NewSession(u.ID, nil)
	require.NoError(ts.T(), err)
	oauthSession.OAuthClientID = &client.ID
	require.NoError(ts.T(), ts.db.Create(oauthSession))

	// Higher-assurance AAL2 session
	aal2Session, err := NewSession(u.ID, nil)
	require.NoError(ts.T(), err)
	aal2Session.AAL = AAL2.PointerString()
	require.NoError(ts.T(), ts.db.Create(aal2Session))

	// Step-up verification invalidates lower-AAL sessions
	require.NoError(ts.T(), InvalidateSessionsWithAALLessThan(ts.db, u.ID, AAL2.String()))

	// Browser AAL1 session should be invalidated
	_, err = FindSessionByID(ts.db, browserSession.ID, false)
	require.ErrorIs(ts.T(), err, SessionNotFoundError{})

	// OAuth client session must be preserved
	foundOAuth, err := FindSessionByID(ts.db, oauthSession.ID, false)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), oauthSession.ID, foundOAuth.ID)

	// AAL2 session must be preserved
	foundAAL2, err := FindSessionByID(ts.db, aal2Session.ID, false)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), aal2Session.ID, foundAAL2.ID)
}

func (ts *SessionsTestSuite) AddClaimAndReloadSession(session *Session, claim AuthenticationMethod) *Session {
	err := AddClaimToSession(ts.db, session.ID, claim)
	require.NoError(ts.T(), err)
	session, err = FindSessionByID(ts.db, session.ID, false)
	require.NoError(ts.T(), err)
	return session
}

func (ts *SessionsTestSuite) TestCalculateAALAndAMR() {
	totalDistinctClaims := 3
	u, err := FindUserByEmailAndAudience(ts.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	session, err := NewSession(u.ID, nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(session))

	session = ts.AddClaimAndReloadSession(session, PasswordGrant)

	firstClaimAddedTime := time.Now()
	session = ts.AddClaimAndReloadSession(session, TOTPSignIn)

	_, _, err = session.CalculateAALAndAMR(u)
	require.NoError(ts.T(), err)

	session = ts.AddClaimAndReloadSession(session, TOTPSignIn)

	identity, err := NewIdentity(u, "sso:95d4a792-4a2a-4523-ae63-bae0631de554", map[string]interface{}{
		"sub": u.GetEmail(),
	})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(identity))
	u.Identities = append(u.Identities, *identity)

	session = ts.AddClaimAndReloadSession(session, SSOSAML)

	aal, amr, err := session.CalculateAALAndAMR(u)
	require.NoError(ts.T(), err)

	require.Equal(ts.T(), AAL2, aal)
	require.Equal(ts.T(), totalDistinctClaims, len(amr))

	found := false
	for _, claim := range session.AMRClaims {
		if claim.GetAuthenticationMethod() == TOTPSignIn.String() {
			require.True(ts.T(), firstClaimAddedTime.Before(claim.UpdatedAt))
			found = true
		}
	}

	for _, claim := range amr {
		if claim.Method == SSOSAML.String() {
			require.Equal(ts.T(), strings.TrimPrefix(identity.Provider, "sso:"), claim.Provider)
		}
	}
	require.True(ts.T(), found)
}

func pointerDuration(value time.Duration) *time.Duration {
	return &value
}

func TestCheckValidity(t *testing.T) {
	start := time.Now()

	examples := []struct {
		name               string
		session            *Session
		highestPossibleAAL AuthenticatorAssuranceLevel
		now                time.Time
		config             SessionValidityConfig
		expected           SessionValidityReason
	}{
		{
			name:               "low aal session past creation time is invalid",
			now:                start.Add(time.Second * 61),
			highestPossibleAAL: AAL2,
			session: &Session{
				AAL:       AAL1.PointerString(),
				CreatedAt: start,
			},
			config: SessionValidityConfig{
				AllowLowAAL: pointerDuration(time.Second * 60),
			},
			expected: SessionLowAAL,
		},
		{
			name:               "high aal session is valid past creation time",
			now:                start.Add(time.Second * 61),
			highestPossibleAAL: AAL2,
			session: &Session{
				AAL:       AAL2.PointerString(),
				CreatedAt: start,
			},
			config: SessionValidityConfig{
				AllowLowAAL: pointerDuration(time.Second * 60),
			},
			expected: SessionValid,
		},
	}

	for _, example := range examples {
		t.Run(example.name, func(t *testing.T) {
			require.Equal(t, example.expected, example.session.CheckValidity(example.config, example.now, &example.now, example.highestPossibleAAL))
		})
	}
}

func TestSessionGetRefreshTokenHmacKey(t *testing.T) {
	s, err := NewSession(uuid.Must(uuid.NewV4()), nil)
	require.NoError(t, err)

	hmacKey, shouldReEncrypt, err := s.GetRefreshTokenHmacKey(conf.DatabaseEncryptionConfiguration{})
	require.NoError(t, err)
	require.Nil(t, hmacKey)
	require.False(t, shouldReEncrypt)

	key := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	s.RefreshTokenHmacKey = &key

	hmacKey, shouldReEncrypt, err = s.GetRefreshTokenHmacKey(conf.DatabaseEncryptionConfiguration{})
	require.NoError(t, err)
	require.Equal(t, make([]byte, 32), hmacKey)
	require.False(t, shouldReEncrypt)
}
