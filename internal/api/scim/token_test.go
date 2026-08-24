package scim

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSCIMToken(t *testing.T) {
	token, digest := NewSCIMToken()

	t.Run("marks the token so that one is recognisable", func(t *testing.T) {
		assert.Regexp(t, `^scim_`, token)
	})

	t.Run("carries 160 bits of randomness", func(t *testing.T) {
		assert.Regexp(t, `^scim_[a-z2-7]{32}$`, token)
	})

	t.Run("returns the SHA-256 digest of the token", func(t *testing.T) {
		sum := sha256.Sum256([]byte(token))

		assert.Equal(t, hex.EncodeToString(sum[:]), digest)
	})

	t.Run("never leaves the token inside the digest", func(t *testing.T) {
		assert.NotContains(t, digest, token)
	})

	t.Run("produces a digest the table will accept", func(t *testing.T) {
		assert.Regexp(t, `^[0-9a-f]{64}$`, digest,
			"scim_tokens_token_hash_check refuses anything else")
	})

	t.Run("mints a different token every time", func(t *testing.T) {
		other, otherDigest := NewSCIMToken()

		assert.NotEqual(t, token, other)
		assert.NotEqual(t, digest, otherDigest)
	})
}

func TestTokenTenantsLookup(t *testing.T) {
	db := newTestDB(t)
	tenants := NewTokenTenants(db)
	ctx := context.Background()

	t.Run("resolves a token to the provider it provisions", func(t *testing.T) {
		provider := newTenant(t, db)
		token := grantToken(t, db, provider)

		resolved, err := tenants.Lookup(ctx, token)

		require.NoError(t, err)
		assert.Equal(t, provider, resolved)
	})

	t.Run("turns away a credential that is not a SCIM token without a query", func(t *testing.T) {
		// A nil connection is the assertion: reaching the database would panic,
		// so an admin JWT never becomes a query or a log line.
		_, err := NewTokenTenants(nil).Lookup(ctx, "eyJhbGciOiJIUzI1NiJ9.e30.signature")

		require.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("reports no tenant for a token that was never granted", func(t *testing.T) {
		unknown, _ := NewSCIMToken()

		_, err := tenants.Lookup(ctx, unknown)

		require.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("reports no tenant for a revoked token", func(t *testing.T) {
		provider := newTenant(t, db)
		token := grantToken(t, db, provider)

		require.NoError(t, db.RawQuery(
			"UPDATE scim_tokens SET revoked_at = now() WHERE sso_provider_id = ?", provider,
		).Exec())

		_, err := tenants.Lookup(ctx, token)

		require.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("reports no tenant for an expired token", func(t *testing.T) {
		provider := newTenant(t, db)
		token := grantToken(t, db, provider)

		require.NoError(t, db.RawQuery(
			"UPDATE scim_tokens SET expires_at = ? WHERE sso_provider_id = ?",
			time.Now().Add(-time.Minute), provider,
		).Exec())

		_, err := tenants.Lookup(ctx, token)

		require.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("honours a token that has not expired yet", func(t *testing.T) {
		provider := newTenant(t, db)
		token := grantToken(t, db, provider)

		require.NoError(t, db.RawQuery(
			"UPDATE scim_tokens SET expires_at = ? WHERE sso_provider_id = ?",
			time.Now().Add(time.Hour), provider,
		).Exec())

		resolved, err := tenants.Lookup(ctx, token)

		require.NoError(t, err)
		assert.Equal(t, provider, resolved)
	})

	// The prior art on the token branch looked the provider up by digest alone,
	// which left a disabled provider's token working.
	t.Run("reports no tenant when the provider is disabled", func(t *testing.T) {
		provider := newTenant(t, db)
		token := grantToken(t, db, provider)

		require.NoError(t, db.RawQuery(
			"UPDATE sso_providers SET disabled = true WHERE id = ?", provider,
		).Exec())

		_, err := tenants.Lookup(ctx, token)

		require.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("records that the token was used", func(t *testing.T) {
		provider := newTenant(t, db)
		token := grantToken(t, db, provider)

		used := func() int {
			var count int
			require.NoError(t, db.RawQuery(
				"SELECT COUNT(*) FROM scim_tokens"+
					" WHERE sso_provider_id = ? AND last_used_at IS NOT NULL",
				provider,
			).First(&count))
			return count
		}

		require.Equal(t, 0, used(), "a token that has never been used has no last_used_at")

		_, err := tenants.Lookup(ctx, token)
		require.NoError(t, err)

		assert.Equal(t, 1, used())
	})

	t.Run("resolves each provider's token to that provider", func(t *testing.T) {
		mine, theirs := newTenant(t, db), newTenant(t, db)
		myToken, theirToken := grantToken(t, db, mine), grantToken(t, db, theirs)

		resolvedMine, err := tenants.Lookup(ctx, myToken)
		require.NoError(t, err)
		resolvedTheirs, err := tenants.Lookup(ctx, theirToken)
		require.NoError(t, err)

		assert.Equal(t, mine, resolvedMine)
		assert.Equal(t, theirs, resolvedTheirs)
	})
}
