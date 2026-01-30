package models

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/storage/test"
)

func BenchmarkFindUserWithRefreshToken(b *testing.B) {
	globalConfig, err := conf.LoadGlobal(modelsTestConfig)
	require.NoError(b, err)

	conn, err := test.SetupDBConnection(globalConfig)
	require.NoError(b, err)
	defer conn.Close()

	// Setup: Create a user with identity and MFA factor
	TruncateAll(conn)

	user, err := NewUser("", "bench@example.com", "password", "authenticated", nil)
	require.NoError(b, err)

	t := time.Now()
	user.EmailConfirmedAt = &t
	require.NoError(b, conn.Create(user))

	// Create an identity
	identity, err := NewIdentity(user, "email", map[string]interface{}{
		"sub":   user.ID.String(),
		"email": user.Email.String(),
	})
	require.NoError(b, err)
	require.NoError(b, conn.Create(identity))

	// Create an MFA factor
	factor := NewFactor(user, "test-factor", "totp", FactorStateUnverified)
	require.NoError(b, conn.Create(factor))

	// Create a refresh token
	refreshToken, err := GrantAuthenticatedUser(conn, user, GrantParams{})
	require.NoError(b, err)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _, _, err := FindUserWithRefreshToken(conn, globalConfig.Security.DBEncryption, refreshToken.Token, false)
		if err != nil {
			b.Fatal(err)
		}
	}
}
