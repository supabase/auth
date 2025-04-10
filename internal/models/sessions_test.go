package models

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/conf"
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
	globalConfig, err := conf.LoadGlobal(modelsTestConfig)
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
			require.NotNil(ts.T(), claim.Provider)
		}
	}
	require.True(ts.T(), found)
}
