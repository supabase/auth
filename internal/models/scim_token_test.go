package models

import (
	"testing"
	"time"
	"uuid"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/storage"
)

type SCIMTokenTestSuite struct {
	suite.Suite
	db       *storage.Connection
	provider *SSOProvider
}

func TestSCIMToken(t *testing.T) {
	ts := &SCIMTokenTestSuite{db: setupSCIMTestDB(t)}
	defer func() { require.NoError(t, ts.db.Close()) }()
	suite.Run(t, ts)
}

func (ts *SCIMTokenTestSuite) SetupTest() {
	require.NoError(ts.T(), TruncateAll(ts.db))
	ts.provider = ts.createProvider()
}

func (ts *SCIMTokenTestSuite) TestCreate() {
	token, plaintext := ts.createToken(nil)

	require.Regexp(ts.T(), `^scim_[0-9a-f]{40}$`, plaintext)
	require.Equal(ts.T(), plaintext[:12], token.Prefix)
	require.NotEqual(ts.T(), plaintext, token.TokenHash)
	require.Equal(ts.T(), uuid.UUID(ts.provider.ID), token.SSOProviderID)
	require.False(ts.T(), token.CreatedAt.IsZero())
	require.Nil(ts.T(), token.ExpiresAt)
	require.Nil(ts.T(), token.RevokedAt)
	require.Nil(ts.T(), token.LastUsedAt)
}

func (ts *SCIMTokenTestSuite) TestTimestampsAreUTC() {
	local := time.Local
	time.Local = time.FixedZone("UTC-7", -7*60*60)
	defer func() { time.Local = local }()

	expiresAt := time.Now().Add(time.Hour)
	token, plaintext := ts.createToken(&expiresAt)
	authenticated, err := AuthenticateSCIMToken(ts.db, plaintext)
	require.NoError(ts.T(), err)
	authenticated = ts.revoke(authenticated)
	found, err := FindSCIMTokensBySSOProvider(ts.db, uuid.UUID(ts.provider.ID))
	require.NoError(ts.T(), err)
	require.Len(ts.T(), found, 1)

	for _, t := range []*SCIMToken{token, authenticated, &found[0]} {
		require.Equal(ts.T(), time.UTC, t.CreatedAt.Location())
		require.Equal(ts.T(), time.UTC, t.ExpiresAt.Location())
	}
	for _, t := range []*SCIMToken{authenticated, &found[0]} {
		require.Equal(ts.T(), time.UTC, t.LastUsedAt.Location())
		require.Equal(ts.T(), time.UTC, t.RevokedAt.Location())
	}
}

func (ts *SCIMTokenTestSuite) TestFindBySSOProvider() {
	active, _ := ts.createToken(nil)
	revoked, _ := ts.createToken(nil)
	ts.revoke(revoked)
	expired, _ := ts.createToken(nil)
	ts.expire(expired)
	_, _, err := CreateSCIMToken(ts.db, uuid.UUID(ts.createProvider().ID), nil)
	require.NoError(ts.T(), err)

	tokens, err := FindSCIMTokensBySSOProvider(ts.db, uuid.UUID(ts.provider.ID))
	require.NoError(ts.T(), err)
	require.Len(ts.T(), tokens, 3)
	require.ElementsMatch(ts.T(), []uuid.UUID{active.ID, revoked.ID, expired.ID}, []uuid.UUID{tokens[0].ID, tokens[1].ID, tokens[2].ID})

	tokens, err = FindActiveSCIMTokensBySSOProvider(ts.db, uuid.UUID(ts.provider.ID))
	require.NoError(ts.T(), err)
	require.Len(ts.T(), tokens, 1)
	require.Equal(ts.T(), active.ID, tokens[0].ID)

	tokens, err = FindActiveSCIMTokensBySSOProvider(ts.db, uuid.NewV4())
	require.NoError(ts.T(), err)
	require.Empty(ts.T(), tokens)
}

func (ts *SCIMTokenTestSuite) TestAuthenticate() {
	token, plaintext := ts.createToken(nil)

	authenticated, err := AuthenticateSCIMToken(ts.db, plaintext)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), token.ID, authenticated.ID)
	require.Equal(ts.T(), uuid.UUID(ts.provider.ID), authenticated.SSOProviderID)
	require.NotNil(ts.T(), authenticated.LastUsedAt)
	first := *authenticated.LastUsedAt

	again, err := AuthenticateSCIMToken(ts.db, plaintext)
	require.NoError(ts.T(), err)
	require.True(ts.T(), first.Equal(*again.LastUsedAt))

	require.NoError(ts.T(), ts.db.RawQuery("UPDATE scim_tokens SET last_used_at = now() - interval '2 minutes' WHERE id = ?", token.ID).Exec())
	stale, err := AuthenticateSCIMToken(ts.db, plaintext)
	require.NoError(ts.T(), err)
	require.True(ts.T(), stale.LastUsedAt.After(first.Add(-time.Minute)))
}

func (ts *SCIMTokenTestSuite) TestAuthenticateRejects() {
	for _, tc := range []struct {
		name  string
		setup func() string
	}{
		{"unknown token", func() string { return "scim_" + "00000000000000000000000000000000000000000" }},
		{"revoked token", func() string {
			token, plaintext := ts.createToken(nil)
			ts.revoke(token)
			return plaintext
		}},
		{"expired token", func() string {
			token, plaintext := ts.createToken(nil)
			ts.expire(token)
			return plaintext
		}},
		{"disabled provider", func() string {
			_, plaintext := ts.createToken(nil)
			ts.provider.Disabled = new(true)
			require.NoError(ts.T(), ts.db.UpdateOnly(ts.provider, "disabled"))
			return plaintext
		}},
		{"scim never enabled", func() string {
			provider := &SSOProvider{}
			require.NoError(ts.T(), ts.db.Create(provider))
			_, plaintext, err := CreateSCIMToken(ts.db, uuid.UUID(provider.ID), nil)
			require.NoError(ts.T(), err)
			return plaintext
		}},
		{"scim disabled", func() string {
			provider := ts.createProvider()
			_, plaintext, err := CreateSCIMToken(ts.db, uuid.UUID(provider.ID), nil)
			require.NoError(ts.T(), err)
			require.NoError(ts.T(), DisableSCIM(ts.db, uuid.UUID(provider.ID)))
			return plaintext
		}},
	} {
		ts.Run(tc.name, func() {
			_, err := AuthenticateSCIMToken(ts.db, tc.setup())
			require.True(ts.T(), IsNotFoundError(err), "%v", err)
		})
	}
}

func (ts *SCIMTokenTestSuite) createProvider() *SSOProvider {
	provider := &SSOProvider{}
	require.NoError(ts.T(), ts.db.Create(provider))
	require.NoError(ts.T(), EnableSCIM(ts.db, uuid.UUID(provider.ID)))
	return provider
}

func (ts *SCIMTokenTestSuite) createToken(expiresAt *time.Time) (*SCIMToken, string) {
	token, plaintext, err := CreateSCIMToken(ts.db, uuid.UUID(ts.provider.ID), expiresAt)
	require.NoError(ts.T(), err)
	return token, plaintext
}

func (ts *SCIMTokenTestSuite) revoke(token *SCIMToken) *SCIMToken {
	revoked, err := RevokeSCIMToken(ts.db, token.SSOProviderID, token.ID)
	require.NoError(ts.T(), err)
	return revoked
}

func (ts *SCIMTokenTestSuite) expire(token *SCIMToken) {
	require.NoError(ts.T(), ts.db.RawQuery(
		"UPDATE scim_tokens SET created_at = now() - interval '2 hours', expires_at = now() - interval '1 hour' WHERE id = ?", token.ID,
	).Exec())
}
