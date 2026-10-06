package models

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/storage"
)

type SCIMSettingsTestSuite struct {
	suite.Suite
	db       *storage.Connection
	provider *SSOProvider
}

func TestSCIMSettings(t *testing.T) {
	ts := &SCIMSettingsTestSuite{db: setupSCIMTestDB(t)}
	defer func() { require.NoError(t, ts.db.Close()) }()
	suite.Run(t, ts)
}

func (ts *SCIMSettingsTestSuite) SetupTest() {
	require.NoError(ts.T(), TruncateAll(ts.db))
	ts.provider = &SSOProvider{}
	require.NoError(ts.T(), ts.db.Create(ts.provider))
}

func (ts *SCIMSettingsTestSuite) TestDeletedWithProvider() {
	require.NoError(ts.T(), EnableSCIM(ts.db, ts.provider.ID))
	require.NoError(ts.T(), ts.db.Destroy(ts.provider))

	count, err := ts.db.Q().Where("sso_provider_id = ?", ts.provider.ID).Count(&SCIMSettings{})
	require.NoError(ts.T(), err)
	require.Zero(ts.T(), count)
}
