package models

import (
	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/conf"
	"github.com/netlify/gotrue/storage"
	"github.com/netlify/gotrue/storage/test"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
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
	if globalConfig.MFA.Enabled {
		suite.Run(t, ts)
	}
}

func (ts *SessionsTestSuite) TestCalculateAALAndAMR() {
	totalDistinctClaims := 2
	u, err := FindUserByEmailAndAudience(ts.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	// TODO(Joel): Replace with CreateSession once MFA feature flag is lifted
	session, err := MFA_CreateSession(ts.db, u, &uuid.Nil)
	require.NoError(ts.T(), err)

	err = AddClaimToSession(ts.db, session, PasswordGrant)
	require.NoError(ts.T(), err)

	firstClaimAddedTime := time.Now().Unix()
	err = AddClaimToSession(ts.db, session, TOTPSignIn)
	require.NoError(ts.T(), err)
	session, err = FindSessionById(ts.db, session.ID)
	require.NoError(ts.T(), err)

	aal, amr := session.CalculateAALAndAMR()
	require.Equal(ts.T(), AAL2.String(), aal)
	require.Equal(ts.T(), totalDistinctClaims, len(amr))

	err = AddClaimToSession(ts.db, session, TOTPSignIn)
	require.NoError(ts.T(), err)

	session, err = FindSessionById(ts.db, session.ID)
	require.NoError(ts.T(), err)

	aal, amr = session.CalculateAALAndAMR()

	require.Equal(ts.T(), AAL2.String(), aal)
	require.Equal(ts.T(), totalDistinctClaims, len(amr))
	found := false
	for _, claim := range session.AMRClaims {
		if claim.AuthenticationMethod == TOTPSignIn.String() {
			require.True(ts.T(), firstClaimAddedTime < claim.UpdatedAt.Unix())
			found = true
		}
	}
	require.True(ts.T(), found)

}
