package models

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf/confload"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/storage/test"
)

func TestIsQueryCanceledError(t *testing.T) {
	db := setupSCIMTestDB(t)
	defer func() { require.NoError(t, db.Close()) }()
	err := db.Transaction(func(tx *storage.Connection) error {
		require.NoError(t, tx.RawQuery("SET LOCAL statement_timeout = '1ms'").Exec())
		return tx.RawQuery("SELECT pg_sleep(1)").Exec()
	})
	require.True(t, IsQueryCanceledError(err), err)
	require.False(t, IsQueryCanceledError(errors.New("other")))
}

func setupSCIMTestDB(t *testing.T) *storage.Connection {
	globalConfig, err := confload.LoadGlobal(modelsTestConfig)
	require.NoError(t, err)
	conn, err := test.SetupDBConnection(globalConfig)
	require.NoError(t, err)
	require.NoError(t, TruncateAll(conn))
	return conn
}
