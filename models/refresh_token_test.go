package models

import (
	"testing"

	"github.com/netlify/gotrue/conf"
	"github.com/netlify/gotrue/storage"
	"github.com/netlify/gotrue/storage/test"
	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type RefreshTokenTestSuite struct {
	suite.Suite
	db *storage.Connection
}

func (ts *RefreshTokenTestSuite) SetupTest() {
	TruncateAll(ts.db)
}

func TestRefreshToken(t *testing.T) {
	globalConfig, err := conf.LoadGlobal(modelsTestConfig)
	require.NoError(t, err)

	conn, err := test.SetupDBConnection(globalConfig)
	require.NoError(t, err)

	ts := &RefreshTokenTestSuite{
		db: conn,
	}
	defer ts.db.Close()

	suite.Run(t, ts)
}

func (ts *RefreshTokenTestSuite) TestGrantAuthenticatedUser() {
	u := ts.createUser()
	r, err := GrantAuthenticatedUser(ts.db, u)
	require.NoError(ts.T(), err)

	require.NotEmpty(ts.T(), r.Token)
	require.Equal(ts.T(), u.ID, r.UserID)
}

func (ts *RefreshTokenTestSuite) TestGrantRefreshTokenSwap() {
	u := ts.createUser()
	r, err := GrantAuthenticatedUser(ts.db, u)
	require.NoError(ts.T(), err)

	s, err := GrantRefreshTokenSwap(ts.db, u, r)
	require.NoError(ts.T(), err)

	_, nr, err := FindUserWithRefreshToken(ts.db, r.Token)
	require.NoError(ts.T(), err)

	require.Equal(ts.T(), r.ID, nr.ID)
	require.True(ts.T(), nr.Revoked, "expected old token to be revoked")

	require.NotEqual(ts.T(), r.ID, s.ID)
	require.Equal(ts.T(), u.ID, s.UserID)
}

func (ts *RefreshTokenTestSuite) TestLogoutSingleRefreshTokenFamily() {
	u := ts.createUser()
	// Create 1st refresh token family.
	r, err := GrantAuthenticatedUser(ts.db, u)
	require.NoError(ts.T(), err)
	s, err := GrantRefreshTokenSwap(ts.db, u, r)
	require.NoError(ts.T(), err)

	// Create 2nd refresh token family.
	t, err := GrantAuthenticatedUser(ts.db, u)
	require.NoError(ts.T(), err)

	// Logout of first refresh token family.
	require.NoError(ts.T(), Logout(ts.db, uuid.Nil, u.ID, r.Token))

	// Check that first refresh token family has been deleted.
	u, r, err = FindUserWithRefreshToken(ts.db, r.Token)
	require.Errorf(ts.T(), err, "expected error when there are no refresh tokens to authenticate. user: %v token: %v", u, r)
	require.True(ts.T(), IsNotFoundError(err), "expected NotFoundError")
	u, s, err = FindUserWithRefreshToken(ts.db, s.Token)
	require.Errorf(ts.T(), err, "expected error when there are no refresh tokens to authenticate. user: %v token: %v", u, s)
	require.True(ts.T(), IsNotFoundError(err), "expected NotFoundError")

	// Check that second refresh token family has not been deleted.
	_, nt, err := FindUserWithRefreshToken(ts.db, t.Token)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), t.ID, nt.ID)
}

func (ts *RefreshTokenTestSuite) TestLogoutAllRefreshTokens() {
	// Create 2 refresh tokens.
	u := ts.createUser()
	r, err := GrantAuthenticatedUser(ts.db, u)
	require.NoError(ts.T(), err)
	s, err := GrantAuthenticatedUser(ts.db, u)
	require.NoError(ts.T(), err)

	require.NoError(ts.T(), Logout(ts.db, uuid.Nil, u.ID, ""))
	
	// Check that both refresh tokens have been deleted.
	u, r, err = FindUserWithRefreshToken(ts.db, r.Token)
	require.Errorf(ts.T(), err, "expected error when there are no refresh tokens to authenticate. user: %v token: %v", u, r)
	require.True(ts.T(), IsNotFoundError(err), "expected NotFoundError")
	u, s, err = FindUserWithRefreshToken(ts.db, s.Token)
	require.Errorf(ts.T(), err, "expected error when there are no refresh tokens to authenticate. user: %v token: %v", u, s)
	require.True(ts.T(), IsNotFoundError(err), "expected NotFoundError")
}

func (ts *RefreshTokenTestSuite) createUser() *User {
	return ts.createUserWithEmail("david@netlify.com")
}

func (ts *RefreshTokenTestSuite) createUserWithEmail(email string) *User {
	user, err := NewUser(uuid.Nil, email, "secret", "test", nil)
	require.NoError(ts.T(), err)

	err = ts.db.Create(user)
	require.NoError(ts.T(), err)

	return user
}
