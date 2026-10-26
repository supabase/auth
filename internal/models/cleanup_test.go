package models

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/supabase/auth/internal/conf/confload"
	"github.com/supabase/auth/internal/storage/test"
)

func TestCleanup(t *testing.T) {
	globalConfig, err := confload.LoadGlobal(modelsTestConfig)
	require.NoError(t, err)
	conn, err := test.SetupDBConnection(globalConfig)
	require.NoError(t, err)

	timebox := 10 * time.Second
	inactivityTimeout := 5 * time.Second
	globalConfig.Sessions.Timebox = &timebox
	globalConfig.Sessions.InactivityTimeout = &inactivityTimeout
	globalConfig.External.AnonymousUsers.Enabled = true

	cleanup := NewCleanup(globalConfig)

	for i := 0; i < 100; i += 1 {
		_, err := cleanup.Clean(conn)
		require.NoError(t, err)
	}
}

func TestCleanupDeletesExpiredRevokedRefreshTokens(t *testing.T) {
	globalConfig, err := confload.LoadGlobal(modelsTestConfig)
	require.NoError(t, err)
	conn, err := test.SetupDBConnection(globalConfig)
	require.NoError(t, err)
	defer conn.Close()

	require.NoError(t, TruncateAll(conn))

	user, err := NewUser("", "cleanup-revoked@example.com", "password", globalConfig.JWT.Aud, nil)
	require.NoError(t, err)
	require.NoError(t, conn.Create(user))

	refreshToken, err := GrantAuthenticatedUser(conn, user, GrantParams{})
	require.NoError(t, err)

	require.NoError(t, conn.RawQuery(
		`update refresh_tokens set revoked = true, updated_at = now() - interval '25 hours' where id = ?`,
		refreshToken.ID,
	).Exec())

	cleanup := NewCleanup(globalConfig)
	for i := 0; i < 100; i++ {
		affected, err := cleanup.Clean(conn)
		require.NoError(t, err)
		if affected > 0 {
			break
		}
	}

	var remaining int
	require.NoError(t, conn.RawQuery(`select count(*) from refresh_tokens where id = ?`, refreshToken.ID).First(&remaining))
	require.Equal(t, 0, remaining)
}
