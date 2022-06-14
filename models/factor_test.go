package models

import (
	"testing"
	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/conf"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/netlify/gotrue/storage"
	"github.com/netlify/gotrue/storage/test"
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

func (ts *FactorTestSuite) TestToggleFactorEnabled() {
	u, err := NewUser(uuid.Nil, "", "", "", "", nil)
	require.NoError(ts.T(), err)

	f, err := NewFactor(u, "A1B2C3", "testfactor-id", "some-secret", "")
	require.NoError(ts.T(), err)

	require.NoError(ts.T(), f.Disable(ts.db))
	require.Equal(ts.T(), false, f.Enabled)

	require.NoError(ts.T(), f.Enable(ts.db))
	require.Equal(ts.T(), true, f.Enabled)

	require.NoError(ts.T(), f.Enable(ts.db))
	require.Equal(ts.T(), true, f.Enabled)

	// Check if we can turn MFA on and off safely
}

func (ts *FactorTestSuite) TestFindFactorsByUser() {
	// Create a user then create a factor
	//u, err := NewUser(uuid.Nil, "", "", "", "", nil)
	//require.NoError(ts.T(), err)
	// f, err := NewFactor(u, "A1B2C3", "testfactor-id")
	//require.NoError(ts.T(), err)


	// FindFactorsByUser(ts.db, u)
	//require.NoError(ts.T(), err)
}

func (ts *FactorTestSuite) TestUpdateFactorSimpleName() {

}
