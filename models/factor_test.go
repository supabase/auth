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

func (ts *FactorTestSuite) TestUpdateStatus() {
	newFactorStatus := "verified"
	u, err := NewUser(uuid.Nil, "", "", "", "", nil)
	require.NoError(ts.T(), err)

	f, err := NewFactor(u, "A1B2C3", "testfactor-id", "some-secret", "disabled", "")
	require.NoError(ts.T(), err)

	require.NoError(ts.T(), f.UpdateStatus(ts.db, newFactorStatus))
	require.Equal(ts.T(), newFactorStatus, f.Status)
}

func (ts *FactorTestSuite) TestUpdateFriendlyName() {
	newSimpleName := "newFactorName"

	u, err := NewUser(uuid.Nil, "", "", "", "", nil)
	require.NoError(ts.T(), err)

	f, err := NewFactor(u, "A1B2C3", "testfactor-id", "some-secret", "disabled", "")
	require.NoError(ts.T(), err)

	require.NoError(ts.T(), f.UpdateFriendlyName(ts.db, newSimpleName))
	require.Equal(ts.T(), newSimpleName, f.FriendlyName)

}
