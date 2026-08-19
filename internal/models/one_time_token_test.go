package models

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/conf/confload"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/storage/test"
)

type OneTimeTokenTestSuite struct {
	suite.Suite
	db     *storage.Connection
	config *conf.GlobalConfiguration
}

func (ts *OneTimeTokenTestSuite) SetupTest() {
	TruncateAll(ts.db)
}

func TestOneTimeToken(t *testing.T) {
	globalConfig, err := confload.LoadGlobal(modelsTestConfig)
	require.NoError(t, err)

	conn, err := test.SetupDBConnection(globalConfig)
	require.NoError(t, err)

	ts := &OneTimeTokenTestSuite{
		db:     conn,
		config: globalConfig,
	}
	defer ts.db.Close()

	suite.Run(t, ts)
}

func (ts *OneTimeTokenTestSuite) createUser() *User {
	user, err := NewUser("", "one-time-token@example.com", "secret", "test", nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(user))
	return user
}

// TestFindOneTimeTokenCandidateList covers the salt cut-over use case: a
// single lookup that matches any of several candidate hashes (e.g. a
// current, salted hash alongside a legacy unsalted fallback).
func (ts *OneTimeTokenTestSuite) TestFindOneTimeTokenCandidateList() {
	u := ts.createUser()

	const actualHash = "actual-hash-value"
	require.NoError(ts.T(), CreateOneTimeToken(ts.db, u.ID, "relates_to not used", actualHash, ConfirmationToken))

	ts.Run("matches when the actual hash is one of several candidates", func() {
		ott, err := FindOneTimeToken(ts.db, []string{"wrong-hash", actualHash}, ConfirmationToken)
		require.NoError(ts.T(), err)
		require.Equal(ts.T(), actualHash, ott.TokenHash)
	})

	ts.Run("matches when the actual hash is the only candidate", func() {
		ott, err := FindOneTimeToken(ts.db, []string{actualHash}, ConfirmationToken)
		require.NoError(ts.T(), err)
		require.Equal(ts.T(), actualHash, ott.TokenHash)
	})

	ts.Run("not found when no candidate matches", func() {
		_, err := FindOneTimeToken(ts.db, []string{"wrong-hash-a", "wrong-hash-b"}, ConfirmationToken)
		require.Error(ts.T(), err)
		require.True(ts.T(), IsNotFoundError(err))
	})
}

// TestFindUserByEmailChangeAndAudienceCandidateList covers the combination
// of the candidate-hash-list mechanism (salted + legacy fallback) with the
// existing "pkce_" prefix retry: a single lookup must match a stored,
// PKCE-prefixed hash against any of the unprefixed candidates.
func (ts *OneTimeTokenTestSuite) TestFindUserByEmailChangeAndAudienceCandidateList() {
	u := ts.createUser()
	u.EmailChange = "changed@example.com"
	require.NoError(ts.T(), ts.db.Update(u))

	const legacyHash = "legacy-unsalted-hash"
	const saltedHash = "current-salted-hash"
	prefixedLegacyHash := "pkce_" + legacyHash

	ts.Run("FindUserByEmailChangeCurrentAndAudience matches a pkce_-prefixed legacy candidate", func() {
		require.NoError(ts.T(), ClearOneTimeTokenForUser(ts.db, u.ID, EmailChangeTokenCurrent))
		require.NoError(ts.T(), CreateOneTimeToken(ts.db, u.ID, u.GetEmail(), prefixedLegacyHash, EmailChangeTokenCurrent))

		found, err := FindUserByEmailChangeCurrentAndAudience(ts.db, u.GetEmail(), []string{saltedHash, legacyHash}, u.Aud)
		require.NoError(ts.T(), err)
		require.Equal(ts.T(), u.ID, found.ID)
	})

	ts.Run("FindUserByEmailChangeNewAndAudience matches a pkce_-prefixed legacy candidate", func() {
		require.NoError(ts.T(), ClearOneTimeTokenForUser(ts.db, u.ID, EmailChangeTokenNew))
		require.NoError(ts.T(), CreateOneTimeToken(ts.db, u.ID, u.EmailChange, prefixedLegacyHash, EmailChangeTokenNew))

		found, err := FindUserByEmailChangeNewAndAudience(ts.db, u.EmailChange, []string{saltedHash, legacyHash}, u.Aud)
		require.NoError(ts.T(), err)
		require.Equal(ts.T(), u.ID, found.ID)
	})

	ts.Run("no match when none of the candidates (prefixed or not) match", func() {
		require.NoError(ts.T(), ClearOneTimeTokenForUser(ts.db, u.ID, EmailChangeTokenCurrent))
		require.NoError(ts.T(), CreateOneTimeToken(ts.db, u.ID, u.GetEmail(), prefixedLegacyHash, EmailChangeTokenCurrent))

		_, err := FindUserByEmailChangeCurrentAndAudience(ts.db, u.GetEmail(), []string{"unrelated-hash"}, u.Aud)
		require.Error(ts.T(), err)
		require.True(ts.T(), IsNotFoundError(err))
	})
}
