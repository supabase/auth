package scim

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api/scim/protocol"
	"github.com/supabase/auth/internal/storage"
)

// grantToken mints a token for a provider and stores its digest, the way an
// operator does by hand until there is an admin API.
func grantToken(t *testing.T, db *storage.Connection, provider string) string {
	t.Helper()

	token, digest := NewSCIMToken()
	require.NoError(t, db.RawQuery(
		"INSERT INTO scim_tokens (sso_provider_id, token_hash) VALUES (?, ?)",
		provider, digest,
	).Exec())

	return token
}

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

func TestCredential(t *testing.T) {
	for _, tc := range []struct{ name, header, expected string }{
		{"a bearer token", "Bearer scim_abc", "scim_abc"},
		{"a lowercase scheme, per RFC 7235", "bearer scim_abc", "scim_abc"},
		{"a mixed case scheme", "BeArEr scim_abc", "scim_abc"},
		{"surrounding whitespace", "Bearer   scim_abc  ", "scim_abc"},
		{"no header at all", "", ""},
		{"another scheme", "Basic dXNlcjpwYXNzd29yZA==", ""},
		{"the scheme with nothing after it", "Bearer ", ""},
		{"the scheme alone", "Bearer", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, BasePath+"/Users", nil)
			if tc.header != "" {
				r.Header.Set("Authorization", tc.header)
			}

			assert.Equal(t, tc.expected, credential(r))
		})
	}
}

func TestServerTenantMiddleware(t *testing.T) {
	db := newTestDB(t)
	provider := newTenant(t, db)
	token := grantToken(t, db, provider)

	srv := NewServer(Config{
		ExternalURL: testExternalURL,
		Users:       NewUserStore(db, testExternalURL),
		Tenants:     NewTokenTenants(db),
	})

	// served reports the tenant the middleware handed the handler, or "" when
	// the middleware answered the request itself.
	served := func(t *testing.T, authorization string) (*httptest.ResponseRecorder, string) {
		t.Helper()

		var seen string
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen, _ = tenantFrom(r.Context())
			w.WriteHeader(http.StatusTeapot)
		})

		r := httptest.NewRequest(http.MethodGet, BasePath+"/Users", nil)
		if authorization != "" {
			r.Header.Set("Authorization", authorization)
		}

		w := httptest.NewRecorder()
		srv.Tenant(next).ServeHTTP(w, r)
		return w, seen
	}

	t.Run("hands the tenant to the handler", func(t *testing.T) {
		w, seen := served(t, "Bearer "+token)

		assert.Equal(t, http.StatusTeapot, w.Code, "the handler ran")
		assert.Equal(t, provider, seen)
	})

	t.Run("answers 401 with a challenge when the token is unknown", func(t *testing.T) {
		unknown, _ := NewSCIMToken()

		w, seen := served(t, "Bearer "+unknown)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, `Bearer realm="SCIM"`, w.Header().Get("WWW-Authenticate"))
		assert.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
		assert.Empty(t, seen, "the handler never ran")
	})

	t.Run("answers 401 when there is no Authorization header", func(t *testing.T) {
		w, seen := served(t, "")

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Empty(t, seen)
	})

	t.Run("says the same thing however the token failed", func(t *testing.T) {
		revoked := grantToken(t, db, provider)
		require.NoError(t, db.RawQuery(
			"UPDATE scim_tokens SET revoked_at = now() WHERE token_hash = ?", hashToken(revoked),
		).Exec())
		unknown, _ := NewSCIMToken()

		revokedResponse, _ := served(t, "Bearer "+revoked)
		unknownResponse, _ := served(t, "Bearer "+unknown)

		assert.Equal(t, unknownResponse.Code, revokedResponse.Code)
		assert.JSONEq(t, unknownResponse.Body.String(), revokedResponse.Body.String(),
			"which way a token failed is not something an unauthenticated caller is owed")
	})
}
