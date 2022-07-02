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
	user, err := NewUser(uuid.Nil, "", "agenericemail@gmail.com", "secret", "test", nil)
	require.NoError(ts.T(), err)

	err = ts.db.Create(user)
	require.NoError(ts.T(), err)

	factor, err := NewFactor(user, "asimplename", "factor-which-shall-not-be-named", "totp", "disabled", "topsecret")
	require.NoError(ts.T(), err)

	err = ts.db.Create(factor)
	require.NoError(ts.T(), err)

	return factor
}
