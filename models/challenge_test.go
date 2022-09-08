package models

import (
	"github.com/netlify/gotrue/conf"
	"github.com/netlify/gotrue/storage"
	"github.com/netlify/gotrue/storage/test"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"testing"
)

type ChallengeTestSuite struct {
	suite.Suite
	db *storage.Connection
}

func TestChallenge(t *testing.T) {
	globalConfig, err := conf.LoadGlobal(modelsTestConfig)
	require.NoError(t, err)
	conn, err := test.SetupDBConnection(globalConfig)
	require.NoError(t, err)
	ts := &ChallengeTestSuite{
		db: conn,
	}
	defer ts.db.Close()
	suite.Run(t, ts)
}

func (ts *ChallengeTestSuite) SetupTest() {
	TruncateAll(ts.db)
}

func (ts *FactorTestSuite) TestFindChallengesByFactorID() {
	u, err := NewUser("", "genericemail@gmail.com", "secret", "test", nil)
	require.NoError(ts.T(), err)
	err = ts.db.Create(u)
	require.NoError(ts.T(), err)
	f, err := NewFactor(u, "asimplename", "totp", FactorUnverifiedState, "topsecret")
	require.NoError(ts.T(), err)
	err = ts.db.Create(f)
	require.NoError(ts.T(), err)
	c, err := NewChallenge(f)
	require.NoError(ts.T(), err)
	err = ts.db.Create(c)
	require.NoError(ts.T(), err)
	n, err := FindChallengesByFactorID(ts.db, c.FactorID)
	require.NoError(ts.T(), err)
	require.Len(ts.T(), n, 1)
}
