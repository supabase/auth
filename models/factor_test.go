package models

import (
	"github.com/gofrs/uuid"
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
	challenge, err := NewChallenge(factor.ID)
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

func (ts *FactorTestSuite) TestToggleFactorEnabled() {
	f := ts.createFactor()
	require.NoError(ts.T(), f.Disable(ts.db))
	require.Equal(ts.T(), false, f.Enabled)

	require.NoError(ts.T(), f.Enable(ts.db))
	require.Equal(ts.T(), true, f.Enabled)

	require.NoError(ts.T(), f.Enable(ts.db))
	require.Equal(ts.T(), true, f.Enabled)

}

func (ts *FactorTestSuite) createFactor() *Factor {
	u, err := NewUser(uuid.Nil, "", "", "", "", nil)
	require.NoError(ts.T(), err)

	err = ts.db.Create(u)
	require.NoError(ts.T(), err)

	f, err := NewFactor(u, "A1B2C3", "testfactor-id", "phone", "supersecretkey")
	require.NoError(ts.T(), err)

	err = ts.db.Create(f)
	require.NoError(ts.T(), err)

	return f
}
