package models

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/conf/confload"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/storage/test"
)

// The caller chooses the validity window, so this suite asserts only what this
// layer owns: the value survives the round trip, and a resend replaces it. The
// per-flow window choice is asserted in the api package.
type OneTimeTokenTestSuite struct {
	suite.Suite
	db     *storage.Connection
	config *conf.GlobalConfiguration
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

func (ts *OneTimeTokenTestSuite) SetupTest() {
	TruncateAll(ts.db)
}

func (ts *OneTimeTokenTestSuite) createUser() *User {
	u, err := NewUser("", "test@example.com", "password", ts.config.JWT.Aud, nil)
	require.NoError(ts.T(), err, "Error creating test user model")
	require.NoError(ts.T(), ts.db.Create(u), "Error saving new test user")
	return u
}

func (ts *OneTimeTokenTestSuite) TestCreateOneTimeToken() {
	cases := map[string]time.Duration{
		"future window": 15 * time.Minute,
		// CreateOneTimeToken neither validates nor clamps the window.
		// The caller owns it. The api verify tests rely on this to build
		// expired tokens.
		"past window": -24 * time.Hour,
	}

	for name, validity := range cases {
		ts.Run(name, func() {
			TruncateAll(ts.db)
			u := ts.createUser()

			before := time.Now()
			require.NoError(ts.T(), CreateOneTimeToken(ts.db, u.ID, u.GetEmail(), name, ConfirmationToken, validity))
			after := time.Now()

			ott, err := FindOneTimeToken(ts.db, name, ConfirmationToken)
			require.NoError(ts.T(), err)
			require.NotNil(ts.T(), ott.ExpiresAt)

			require.False(ts.T(), ott.ExpiresAt.Before(before.Add(validity)),
				"expires_at %s precedes the window opened at %s", ott.ExpiresAt, before.Add(validity))
			require.False(ts.T(), ott.ExpiresAt.After(after.Add(validity)),
				"expires_at %s follows the window closed at %s", ott.ExpiresAt, after.Add(validity))
		})
	}
}

func (ts *OneTimeTokenTestSuite) TestCreateOneTimeTokenResendReplacesWindow() {
	u := ts.createUser()

	require.NoError(ts.T(), CreateOneTimeToken(ts.db, u.ID, u.GetEmail(), "first-hash", ConfirmationToken, time.Minute))
	first, err := FindOneTimeToken(ts.db, "first-hash", ConfirmationToken)
	require.NoError(ts.T(), err)
	require.NotNil(ts.T(), first.ExpiresAt)

	require.NoError(ts.T(), CreateOneTimeToken(ts.db, u.ID, u.GetEmail(), "second-hash", ConfirmationToken, time.Hour))

	_, err = FindOneTimeToken(ts.db, "first-hash", ConfirmationToken)
	require.True(ts.T(), IsNotFoundError(err), "resend must clear the previous token, got %v", err)

	second, err := FindOneTimeToken(ts.db, "second-hash", ConfirmationToken)
	require.NoError(ts.T(), err)
	require.NotNil(ts.T(), second.ExpiresAt)
	require.True(ts.T(), second.ExpiresAt.After(*first.ExpiresAt),
		"resend must move expires_at forward, first=%s second=%s", first.ExpiresAt, second.ExpiresAt)
}

func (ts *OneTimeTokenTestSuite) TestFindOneTimeTokenWithPKCEFallback() {
	ts.Run("exact hash match", func() {
		TruncateAll(ts.db)
		u := ts.createUser()
		require.NoError(ts.T(), CreateOneTimeToken(ts.db, u.ID, u.GetEmail(), "hash", ConfirmationToken, time.Minute))

		ott, err := FindOneTimeTokenWithPKCEFallback(ts.db, u.ID, "hash", ConfirmationToken)
		require.NoError(ts.T(), err)
		require.Equal(ts.T(), "hash", ott.TokenHash)
		require.Equal(ts.T(), u.ID, ott.UserID)
	})

	ts.Run("falls back to pkce_ prefixed hash", func() {
		TruncateAll(ts.db)
		u := ts.createUser()
		require.NoError(ts.T(), CreateOneTimeToken(ts.db, u.ID, u.GetEmail(), "pkce_hash", ConfirmationToken, time.Minute))

		ott, err := FindOneTimeTokenWithPKCEFallback(ts.db, u.ID, "hash", ConfirmationToken)
		require.NoError(ts.T(), err)
		require.Equal(ts.T(), "pkce_hash", ott.TokenHash)
		require.Equal(ts.T(), u.ID, ott.UserID)
	})

	ts.Run("prefers exact match over pkce_ prefixed hash", func() {
		TruncateAll(ts.db)
		u := ts.createUser()

		// (user_id, token_type) is unique, so the two candidates have to be
		// different types. Both types are passed so both are eligible.
		require.NoError(ts.T(), CreateOneTimeToken(ts.db, u.ID, u.GetEmail(), "hash", ConfirmationToken, time.Minute))
		require.NoError(ts.T(), CreateOneTimeToken(ts.db, u.ID, u.GetEmail(), "pkce_hash", RecoveryToken, time.Minute))

		ott, err := FindOneTimeTokenWithPKCEFallback(ts.db, u.ID, "hash", ConfirmationToken, RecoveryToken)
		require.NoError(ts.T(), err)
		require.Equal(ts.T(), "hash", ott.TokenHash)
		require.Equal(ts.T(), ConfirmationToken, ott.TokenType)
	})

	ts.Run("not found when neither hash exists", func() {
		TruncateAll(ts.db)
		u := ts.createUser()

		ott, err := FindOneTimeTokenWithPKCEFallback(ts.db, u.ID, "missing", ConfirmationToken)
		require.True(ts.T(), IsNotFoundError(err), "expected not found error, got %v", err)
		require.Nil(ts.T(), ott)
	})

	ts.Run("does not leak across users on the pkce_ fallback", func() {
		TruncateAll(ts.db)
		owner := ts.createUser()
		require.NoError(ts.T(), CreateOneTimeToken(ts.db, owner.ID, owner.GetEmail(), "pkce_hash", ConfirmationToken, time.Minute))

		other, err := NewUser("", "other@example.com", "password", ts.config.JWT.Aud, nil)
		require.NoError(ts.T(), err)
		require.NoError(ts.T(), ts.db.Create(other))

		ott, err := FindOneTimeTokenWithPKCEFallback(ts.db, other.ID, "hash", ConfirmationToken)
		require.True(ts.T(), IsNotFoundError(err), "expected not found error, got %v", err)
		require.Nil(ts.T(), ott)
	})

	ts.Run("token type filter applies to the pkce_ fallback", func() {
		TruncateAll(ts.db)
		u := ts.createUser()
		require.NoError(ts.T(), CreateOneTimeToken(ts.db, u.ID, u.GetEmail(), "pkce_hash", RecoveryToken, time.Minute))

		ott, err := FindOneTimeTokenWithPKCEFallback(ts.db, u.ID, "hash", ConfirmationToken)
		require.True(ts.T(), IsNotFoundError(err), "expected not found error, got %v", err)
		require.Nil(ts.T(), ott)
	})
}

func (ts *OneTimeTokenTestSuite) TestFindOneTimeTokenByUserID() {
	u := ts.createUser()

	require.NoError(ts.T(), CreateOneTimeToken(ts.db, u.ID, u.GetEmail(), "confirmation-hash", ConfirmationToken, time.Hour))
	require.NoError(ts.T(), CreateOneTimeToken(ts.db, u.ID, u.GetEmail(), "recovery-hash", RecoveryToken, time.Hour))

	ts.Run("returns the row for the requested token type", func() {
		ott, err := FindOneTimeTokenByUserID(ts.db, u.ID, "confirmation-hash", ConfirmationToken)
		require.NoError(ts.T(), err)
		require.Equal(ts.T(), "confirmation-hash", ott.TokenHash)
		require.Equal(ts.T(), ConfirmationToken, ott.TokenType)
	})

	ts.Run("accepts two token types", func() {
		ott, err := FindOneTimeTokenByUserID(ts.db, u.ID, "recovery-hash", ConfirmationToken, RecoveryToken)
		require.NoError(ts.T(), err)
		require.Equal(ts.T(), "recovery-hash", ott.TokenHash)
		require.Equal(ts.T(), RecoveryToken, ott.TokenType)
	})

	ts.Run("does not leak across token types", func() {
		ott, err := FindOneTimeTokenByUserID(ts.db, u.ID, "confirmation-hash", RecoveryToken)
		require.True(ts.T(), IsNotFoundError(err), "expected not found error, got %v", err)
		require.Nil(ts.T(), ott)
	})

	ts.Run("wrong hash for the right user is a not found error", func() {
		ott, err := FindOneTimeTokenByUserID(ts.db, u.ID, "wrong-hash", ConfirmationToken)
		require.True(ts.T(), IsNotFoundError(err), "expected not found error, got %v", err)
		require.Nil(ts.T(), ott)
	})

	ts.Run("does not leak across users", func() {
		other, err := NewUser("", "other@example.com", "password", ts.config.JWT.Aud, nil)
		require.NoError(ts.T(), err)
		require.NoError(ts.T(), ts.db.Create(other))

		// Same hash and type as u's token, different user.
		ott, err := FindOneTimeTokenByUserID(ts.db, other.ID, "confirmation-hash", ConfirmationToken)
		require.True(ts.T(), IsNotFoundError(err), "expected not found error, got %v", err)
		require.Nil(ts.T(), ott)
	})
}
