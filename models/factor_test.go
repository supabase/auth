package models

import (
	"github.com/netlify/gotrue/conf"
	"github.com/netlify/gotrue/storage"
	"github.com/netlify/gotrue/storage/test"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"testing"
)

type FactorTestSuite struct {
	suite.Suite
	db *storage.Connection
}

func TestFactor(t *testing.T) {
	globalConfig, err := conf.LoadGlobal(modelsTestConfig)
	require.NoError(t, err)
	conn, err := test.SetupDBConnection(globalConfig)
	require.NoError(t, err)
	ts := &FactorTestSuite{
		db: conn,
	}
	defer ts.db.Close()
	suite.Run(t, ts)
}
func (ts *FactorTestSuite) TestFindFactorByChallengeID() {
	factor := ts.createFactor()
	challenge, err := NewChallenge(factor)
	require.NoError(ts.T(), err)

	err = ts.db.Create(challenge)
	require.NoError(ts.T(), err)

	n, err := FindFactorByChallengeID(ts.db, challenge.ID)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), factor.ID, n.ID)
}

func (ts *FactorTestSuite) SetupTest() {
	TruncateAll(ts.db)
}

func (ts *FactorTestSuite) TestFindFactorByFriendlyName() {
	f := ts.createFactor()
	n, err := FindFactorByFriendlyName(ts.db, f.FriendlyName)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), f.ID, n.ID)
}

func (ts *FactorTestSuite) TestFindFactorByFactorID() {
	f := ts.createFactor()
	n, err := FindFactorByFactorID(ts.db, f.ID)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), f.ID, n.ID)
}

func (ts *FactorTestSuite) createFactor() *Factor {
	user, err := NewUser("", "agenericemail@gmail.com", "secret", "test", nil)
	require.NoError(ts.T(), err)

	err = ts.db.Create(user)
	require.NoError(ts.T(), err)

	factor, err := NewFactor(user, "asimplename", "factor-which-shall-not-be-named", "totp", "disabled", "topsecret")
	require.NoError(ts.T(), err)

	err = ts.db.Create(factor)
	require.NoError(ts.T(), err)

	return factor
}
func (ts *FactorTestSuite) TestUpdateStatus() {
	newFactorStatus := FactorVerifiedState
	u, err := NewUser("", "", "", "", nil)
	require.NoError(ts.T(), err)

	f, err := NewFactor(u, "A1B2C3", "testfactor-id", "some-secret", FactorUnverifiedState, "")
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), f.UpdateStatus(ts.db, newFactorStatus))
	require.Equal(ts.T(), newFactorStatus, f.Status)
}

func (ts *FactorTestSuite) TestUpdateFriendlyName() {
	newSimpleName := "newFactorName"
	u, err := NewUser("", "", "", "", nil)
	require.NoError(ts.T(), err)

	f, err := NewFactor(u, "A1B2C3", "testfactor-id", "some-secret", FactorUnverifiedState, "")
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), f.UpdateFriendlyName(ts.db, newSimpleName))
	require.Equal(ts.T(), newSimpleName, f.FriendlyName)
}
