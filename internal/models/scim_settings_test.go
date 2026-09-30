package models

import (
	"sync"
	"testing"

	"github.com/gofrs/uuid"
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

func (ts *SCIMSettingsTestSuite) TestDisabledByDefault() {
	require.False(ts.T(), ts.enabled())
}

func (ts *SCIMSettingsTestSuite) TestTransitions() {
	for _, step := range []struct {
		name    string
		apply   func(*storage.Connection, uuid.UUID) (bool, error)
		changed bool
		enabled bool
	}{
		{"disable never enabled", DisableSCIM, false, false},
		{"enable", EnableSCIM, true, true},
		{"enable again", EnableSCIM, false, true},
		{"disable", DisableSCIM, true, false},
		{"disable again", DisableSCIM, false, false},
		{"re-enable", EnableSCIM, true, true},
	} {
		changed, err := step.apply(ts.db, ts.provider.ID)
		require.NoError(ts.T(), err, step.name)
		require.Equal(ts.T(), step.changed, changed, step.name)
		require.Equal(ts.T(), step.enabled, ts.enabled(), step.name)
	}
}

func (ts *SCIMSettingsTestSuite) TestConcurrentEnableChangesOnce() {
	type result struct {
		changed bool
		err     error
	}
	var wg sync.WaitGroup
	results := make(chan result, 10)
	for range 10 {
		wg.Go(func() {
			changed, err := EnableSCIM(ts.db, ts.provider.ID)
			results <- result{changed, err}
		})
	}
	wg.Wait()
	close(results)

	changes := 0
	for r := range results {
		require.NoError(ts.T(), r.err)
		if r.changed {
			changes++
		}
	}
	require.Equal(ts.T(), 1, changes)
	require.True(ts.T(), ts.enabled())
}

func (ts *SCIMSettingsTestSuite) TestDeletedWithProvider() {
	_, err := EnableSCIM(ts.db, ts.provider.ID)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Destroy(ts.provider))

	count, err := ts.db.Q().Where("sso_provider_id = ?", ts.provider.ID).Count(&SCIMSettings{})
	require.NoError(ts.T(), err)
	require.Zero(ts.T(), count)
}

func (ts *SCIMSettingsTestSuite) enabled() bool {
	enabled, err := IsSCIMEnabled(ts.db, ts.provider.ID)
	require.NoError(ts.T(), err)
	return enabled
}
