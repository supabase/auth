package models

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/storage/test"
)

type RefreshTokenTestSuite struct {
	suite.Suite
	db *storage.Connection
}

func (ts *RefreshTokenTestSuite) SetupTest() {
	TruncateAll(ts.db)

	project_id := uuid.Must(uuid.NewV4())
	// Create a project
	if err := ts.db.RawQuery(fmt.Sprintf("INSERT INTO auth.projects (id, name) VALUES ('%s', 'test_project')", project_id)).Exec(); err != nil {
		panic(err)
	}

	// Create the admin of the organization
	user, err := NewUser("", "admin@example.com", "test", "", nil, uuid.Nil, project_id)
	require.NoError(ts.T(), err, "Error making new user")
	require.NoError(ts.T(), ts.db.Create(user, "organization_id", "organization_role"), "Error creating user")

	// Create the organization
	organization_id := uuid.Must(uuid.FromString("123e4567-e89b-12d3-a456-426655440000"))
	if err := ts.db.RawQuery(fmt.Sprintf("INSERT INTO auth.organizations (id, name, project_id, admin_id) VALUES ('%s', 'test_organization', '%s', '%s')", organization_id, project_id, user.ID)).Exec(); err != nil {
		panic(err)
	}

	// Set the user as the admin of the organization
	if err := ts.db.RawQuery(fmt.Sprintf("UPDATE auth.users SET organization_id = '%s', organization_role='admin' WHERE id = '%s'", organization_id, user.ID)).Exec(); err != nil {
		panic(err)
	}
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
	r, err := GrantAuthenticatedUser(ts.db, u, GrantParams{})
	require.NoError(ts.T(), err)

	require.NotEmpty(ts.T(), r.Token)
	require.Equal(ts.T(), u.ID, r.UserID)
}

func (ts *RefreshTokenTestSuite) TestGrantRefreshTokenSwap() {
	u := ts.createUser()
	r, err := GrantAuthenticatedUser(ts.db, u, GrantParams{})
	require.NoError(ts.T(), err)

	s, err := GrantRefreshTokenSwap(&http.Request{}, ts.db, u, r)
	require.NoError(ts.T(), err)

	_, nr, _, err := FindUserWithRefreshToken(ts.db, r.Token, false)
	require.NoError(ts.T(), err)

	require.Equal(ts.T(), r.ID, nr.ID)
	require.True(ts.T(), nr.Revoked, "expected old token to be revoked")

	require.NotEqual(ts.T(), r.ID, s.ID)
	require.Equal(ts.T(), u.ID, s.UserID)
}

func (ts *RefreshTokenTestSuite) TestLogout() {
	u := ts.createUser()
	r, err := GrantAuthenticatedUser(ts.db, u, GrantParams{})
	require.NoError(ts.T(), err)

	require.NoError(ts.T(), Logout(ts.db, u.ID))
	u, r, _, err = FindUserWithRefreshToken(ts.db, r.Token, false)
	require.Errorf(ts.T(), err, "expected error when there are no refresh tokens to authenticate. user: %v token: %v", u, r)

	require.True(ts.T(), IsNotFoundError(err), "expected NotFoundError")
}

func (ts *RefreshTokenTestSuite) createUser() *User {
	return ts.createUserWithEmail("david@netlify.com")
}

func (ts *RefreshTokenTestSuite) createUserWithEmail(email string) *User {
	id := uuid.Must(uuid.FromString("123e4567-e89b-12d3-a456-426655440000"))
	user, err := NewUser("", email, "secret", "test", nil, id, uuid.Nil)
	require.NoError(ts.T(), err)

	err = ts.db.Create(user, "project_id", "organization_role")
	require.NoError(ts.T(), err)

	return user
}
