package models

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/clanwyse/halo/internal/conf"
	"github.com/clanwyse/halo/internal/storage/test"
)

func TestCleanup(t *testing.T) {
	globalConfig, err := conf.LoadGlobal(modelsTestConfig)
	require.NoError(t, err)
	conn, err := test.SetupDBConnection(globalConfig)
	require.NoError(t, err)

	sessionTimebox := 10 * time.Second
	sessionInactivityTimeout := 5 * time.Second

	cleanup := &Cleanup{
		SessionTimebox:           &sessionTimebox,
		SessionInactivityTimeout: &sessionInactivityTimeout,
	}

	cleanup.Setup()

	for i := 0; i < 100; i += 1 {
		_, err := cleanup.Clean(conn)
		require.NoError(t, err)
	}
}
