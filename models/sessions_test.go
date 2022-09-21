package models

import (
	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/conf"
	"github.com/netlify/gotrue/storage"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
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
	user, err := NewUser("", email, "secret", "test", nil)
	require.NoError(ts.T(), err)

	err = ts.db.Create(user)
	require.NoError(ts.T(), err)
}

func (ts *SessionsTestSuite) TestCalculateAALAndAMR() {
	totalDistinctClaims := 2
	u, err := FindUserByEmailAndAudience(ts.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	session, err := CreateSession(ts.db, u, &uuid.Nil)
	require.NoError(ts.T(), err)

	err = AddClaimToSession(ts.db, session, PasswordGrant.String())
	require.NoError(ts.T(), err)

	firstClaimAddedTime := time.Now().Unix()
	err = AddClaimToSession(ts.db, session, TOTP.String())
	require.NoError(ts.T(), err)

	aal, amr := session.CalculateAALAndAMR()

	require.Equal(ts.T(), AAL2.String(), aal)
	require.Equal(ts.T(), totalDistinctClaims, len(amr))

	err = AddClaimToSession(ts.db, session, TOTP.String())
	require.NoError(ts.T(), err)

	aal, amr = session.CalculateAALAndAMR()

	require.Equal(ts.T(), AAL2.String(), aal)
	require.Equal(ts.T(), totalDistinctClaims, len(amr))
	found := false
	for _, claim := range session.AMRClaims {
		if claim.AuthenticationMethod == TOTP.String() {
			require.True(ts.T(), firstClaimAddedTime < claim.UpdatedAt.Unix())
			found = true
		}
	}
	require.True(ts.T(), found)

}
