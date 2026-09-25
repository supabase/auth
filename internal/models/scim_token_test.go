package models

import (
	"regexp"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/conf/confload"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/storage/test"
)

type SCIMTokenTestSuite struct {
	suite.Suite
	db       *storage.Connection
	provider *SSOProvider
}

func TestSCIMToken(t *testing.T) {
	globalConfig, err := confload.LoadGlobal(modelsTestConfig)
	require.NoError(t, err)
	conn, err := test.SetupDBConnection(globalConfig)
	require.NoError(t, err)
	ts := &SCIMTokenTestSuite{db: conn}
	defer ts.db.Close()
	suite.Run(t, ts)
}

func (ts *SCIMTokenTestSuite) SetupTest() {
	require.NoError(ts.T(), TruncateAll(ts.db))
	ts.provider = ts.createProvider()
}

func (ts *SCIMTokenTestSuite) createProvider() *SSOProvider {
	provider := &SSOProvider{}
	require.NoError(ts.T(), ts.db.Create(provider))
	return provider
}

func (ts *SCIMTokenTestSuite) createToken(expiresAt *time.Time) (*SCIMToken, string) {
	token, plaintext, err := CreateSCIMToken(ts.db, ts.provider, expiresAt)
	require.NoError(ts.T(), err)
	return token, plaintext
}

func (ts *SCIMTokenTestSuite) TestCreate() {
	token, plaintext := ts.createToken(nil)

	require.Regexp(ts.T(), regexp.MustCompile(`^scim_[0-9a-f]{40}$`), plaintext)
	require.Equal(ts.T(), plaintext[:12], token.Prefix)
	require.Equal(ts.T(), HashSCIMToken(plaintext), token.TokenHash)
	require.NotEqual(ts.T(), plaintext, token.TokenHash)
	require.Equal(ts.T(), ts.provider.ID, token.SSOProviderID)
	require.False(ts.T(), token.CreatedAt.IsZero())
	require.Nil(ts.T(), token.ExpiresAt)
	require.Nil(ts.T(), token.RevokedAt)
	require.Nil(ts.T(), token.LastUsedAt)
}

func (ts *SCIMTokenTestSuite) TestCreateWithExpiry() {
	expiresAt := time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)
	token, _ := ts.createToken(&expiresAt)

	require.NotNil(ts.T(), token.ExpiresAt)
	require.True(ts.T(), expiresAt.Equal(*token.ExpiresAt))
}

func (ts *SCIMTokenTestSuite) TestCreateWithPastExpiry() {
	expiresAt := time.Now().Add(-time.Minute)
	_, _, err := CreateSCIMToken(ts.db, ts.createProvider(), &expiresAt)

	require.ErrorIs(ts.T(), err, SCIMTokenExpiryError{})
}

func (ts *SCIMTokenTestSuite) TestTimestampsAreUTC() {
	local := time.Local
	time.Local = time.FixedZone("UTC-7", -7*60*60)
	defer func() { time.Local = local }()

	expiresAt := time.Now().Add(time.Hour)
	token, plaintext := ts.createToken(&expiresAt)
	authenticated, err := AuthenticateSCIMToken(ts.db, plaintext)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), authenticated.Revoke(ts.db))
	found, err := FindSCIMTokensBySSOProvider(ts.db, ts.provider.ID)
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

func (ts *SCIMTokenTestSuite) TestCreateForMissingProvider() {
	_, _, err := CreateSCIMToken(ts.db, &SSOProvider{ID: uuid.Must(uuid.NewV4())}, nil)

	require.Error(ts.T(), err)
}

func (ts *SCIMTokenTestSuite) TestFindBySSOProvider() {
	first, _ := ts.createToken(nil)
	second, _ := ts.createToken(nil)
	require.NoError(ts.T(), second.Revoke(ts.db))

	other := ts.createProvider()
	_, _, err := CreateSCIMToken(ts.db, other, nil)
	require.NoError(ts.T(), err)

	tokens, err := FindSCIMTokensBySSOProvider(ts.db, ts.provider.ID)
	require.NoError(ts.T(), err)
	require.Len(ts.T(), tokens, 2)
	require.ElementsMatch(ts.T(), []uuid.UUID{first.ID, second.ID}, []uuid.UUID{tokens[0].ID, tokens[1].ID})
}

func (ts *SCIMTokenTestSuite) TestFindByPrefix() {
	token, _ := ts.createToken(nil)

	found, err := FindSCIMTokenByPrefix(ts.db, ts.provider.ID, token.Prefix)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), token.ID, found.ID)

	_, err = FindSCIMTokenByPrefix(ts.db, ts.createProvider().ID, token.Prefix)
	require.True(ts.T(), IsNotFoundError(err))

	_, err = FindSCIMTokenByPrefix(ts.db, ts.provider.ID, "scim_0000000")
	require.True(ts.T(), IsNotFoundError(err))
}

func (ts *SCIMTokenTestSuite) TestFindByPrefixAmbiguous() {
	token, _ := ts.createToken(nil)
	duplicate := &SCIMToken{
		ID:            uuid.Must(uuid.NewV4()),
		SSOProviderID: ts.provider.ID,
		TokenHash:     HashSCIMToken("duplicate"),
		Prefix:        token.Prefix,
	}
	require.NoError(ts.T(), ts.db.RawQuery(
		"INSERT INTO scim_tokens (id, sso_provider_id, token_hash, prefix) VALUES (?, ?, ?, ?)",
		duplicate.ID, duplicate.SSOProviderID, duplicate.TokenHash, duplicate.Prefix,
	).Exec())

	_, err := FindSCIMTokenByPrefix(ts.db, ts.provider.ID, token.Prefix)
	require.Error(ts.T(), err)
	require.False(ts.T(), IsNotFoundError(err))
}

func (ts *SCIMTokenTestSuite) TestRevoke() {
	token, _ := ts.createToken(nil)

	require.NoError(ts.T(), token.Revoke(ts.db))
	require.NotNil(ts.T(), token.RevokedAt)
	revokedAt := *token.RevokedAt

	require.NoError(ts.T(), token.Revoke(ts.db))
	require.True(ts.T(), revokedAt.Equal(*token.RevokedAt))

	reloaded, err := FindSCIMTokenByPrefix(ts.db, ts.provider.ID, token.Prefix)
	require.NoError(ts.T(), err)
	require.True(ts.T(), revokedAt.Equal(*reloaded.RevokedAt))
}

func (ts *SCIMTokenTestSuite) TestAuthenticate() {
	token, plaintext := ts.createToken(nil)

	authenticated, err := AuthenticateSCIMToken(ts.db, plaintext)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), token.ID, authenticated.ID)
	require.Equal(ts.T(), ts.provider.ID, authenticated.SSOProviderID)
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
	disabled := true

	for _, tc := range []struct {
		name  string
		setup func() string
	}{
		{"unknown token", func() string { return "scim_" + "00000000000000000000000000000000000000000" }},
		{"revoked token", func() string {
			token, plaintext := ts.createToken(nil)
			require.NoError(ts.T(), token.Revoke(ts.db))
			return plaintext
		}},
		{"expired token", func() string {
			token, plaintext := ts.createToken(nil)
			require.NoError(ts.T(), ts.db.RawQuery(
				"UPDATE scim_tokens SET created_at = now() - interval '2 hours', expires_at = now() - interval '1 hour' WHERE id = ?", token.ID,
			).Exec())
			return plaintext
		}},
		{"disabled provider", func() string {
			_, plaintext := ts.createToken(nil)
			ts.provider.Disabled = &disabled
			require.NoError(ts.T(), ts.db.UpdateOnly(ts.provider, "disabled"))
			return plaintext
		}},
	} {
		ts.Run(tc.name, func() {
			_, err := AuthenticateSCIMToken(ts.db, tc.setup())
			require.True(ts.T(), IsNotFoundError(err), "%v", err)
		})
	}
}
