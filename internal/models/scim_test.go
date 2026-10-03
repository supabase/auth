package models

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf/confload"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/storage/test"
)

func setupSCIMTestDB(t *testing.T) *storage.Connection {
	globalConfig, err := confload.LoadGlobal(modelsTestConfig)
	require.NoError(t, err)
	conn, err := test.SetupDBConnection(globalConfig)
	require.NoError(t, err)
	require.NoError(t, TruncateAll(conn))
	return conn
}

func createSCIMTestProvider(t require.TestingT, db *storage.Connection) *SSOProvider {
	provider := &SSOProvider{}
	require.NoError(t, db.Create(provider))
	_, err := EnableSCIM(db, provider.ID)
	require.NoError(t, err)
	return provider
}
