package models

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/supabase/gotrue/internal/conf"
	"github.com/supabase/gotrue/internal/storage/test"
)

func TestCleanupSQL(t *testing.T) {
	globalConfig, err := conf.LoadGlobal(modelsTestConfig)
	require.NoError(t, err)
	conn, err := test.SetupDBConnection(globalConfig)
	require.NoError(t, err)

	for _, statement := range CleanupStatements {
		_, err := conn.RawQuery(statement).ExecWithCount()
		require.NoError(t, err, statement)
	}
}

func TestCleanup(t *testing.T) {
	globalConfig, err := conf.LoadGlobal(modelsTestConfig)
	require.NoError(t, err)
	conn, err := test.SetupDBConnection(globalConfig)
	require.NoError(t, err)

	for _, statement := range CleanupStatements {
		_, err := Cleanup(conn)
		if err != nil {
			fmt.Printf("%v %t\n", err, err)
		}
		require.NoError(t, err, statement)
	}
}
