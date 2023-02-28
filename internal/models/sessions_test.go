package models

import (
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/gotrue/internal/conf"
	"github.com/supabase/gotrue/internal/storage"
	"github.com/supabase/gotrue/internal/storage/test"
	"testing"
	"time"
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

func (ts *SessionsTestSuite) TestCalculateAALAndAMR() {
	totalDistinctClaims := 2
	u, err := FindUserByEmailAndAudience(ts.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	session, err := NewSession()
	require.NoError(ts.T(), err)
	session.UserID = u.ID
	require.NoError(ts.T(), ts.db.Create(session))

	err = AddClaimToSession(ts.db, session, PasswordGrant)
	require.NoError(ts.T(), err)

	firstClaimAddedTime := time.Now()
	err = AddClaimToSession(ts.db, session, TOTPSignIn)
	require.NoError(ts.T(), err)
	session, err = FindSessionByID(ts.db, session.ID)
	require.NoError(ts.T(), err)

	aal, amr, err := session.CalculateAALAndAMR(ts.db)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), AAL2.String(), aal)
	require.Equal(ts.T(), totalDistinctClaims, len(amr))

	err = AddClaimToSession(ts.db, session, TOTPSignIn)
	require.NoError(ts.T(), err)

	session, err = FindSessionByID(ts.db, session.ID)
	require.NoError(ts.T(), err)

	aal, amr, err = session.CalculateAALAndAMR(ts.db)
	require.NoError(ts.T(), err)

	require.Equal(ts.T(), AAL2.String(), aal)
	require.Equal(ts.T(), totalDistinctClaims, len(amr))
	found := false
	for _, claim := range session.AMRClaims {
		if claim.GetAuthenticationMethod() == TOTPSignIn.String() {
			require.True(ts.T(), firstClaimAddedTime.Before(claim.UpdatedAt))
			found = true
		}
	}
	require.True(ts.T(), found)

}
