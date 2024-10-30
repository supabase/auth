package models

import (
	"fmt"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/storage/test"
)

type IdentityTestSuite struct {
	suite.Suite
	db *storage.Connection
}

func (ts *IdentityTestSuite) SetupTest() {
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

func TestIdentity(t *testing.T) {
	globalConfig, err := conf.LoadGlobal(modelsTestConfig)
	require.NoError(t, err)

	conn, err := test.SetupDBConnection(globalConfig)
	require.NoError(t, err)

	ts := &IdentityTestSuite{
		db: conn,
	}
	defer ts.db.Close()

	suite.Run(t, ts)
}

func (ts *IdentityTestSuite) TestNewIdentity() {
	u := ts.createUserWithEmail("test@supabase.io")
	ts.Run("Test create identity with no provider id", func() {
		identityData := map[string]interface{}{}
		_, err := NewIdentity(u, "email", identityData)
		require.Error(ts.T(), err, "Error missing provider id")
	})

	ts.Run("Test create identity successfully", func() {
		identityData := map[string]interface{}{"sub": uuid.Nil.String()}
		identity, err := NewIdentity(u, "email", identityData)
		require.NoError(ts.T(), err)
		require.Equal(ts.T(), u.ID, identity.UserID)
	})
}

func (ts *IdentityTestSuite) TestFindUserIdentities() {
	u := ts.createUserWithIdentity("test@supabase.io")
	identities, err := FindIdentitiesByUserID(ts.db, u.ID)
	require.NoError(ts.T(), err)

	require.Len(ts.T(), identities, 1)

}

func (ts *IdentityTestSuite) TestUpdateIdentityData() {
	u := ts.createUserWithIdentity("test@supabase.io")

	identities, err := FindIdentitiesByUserID(ts.db, u.ID)
	require.NoError(ts.T(), err)

	updates := map[string]interface{}{
		"sub":   nil,
		"name":  nil,
		"email": nil,
	}
	for _, identity := range identities {
		err := identity.UpdateIdentityData(ts.db, updates)
		require.NoError(ts.T(), err)
	}

	updatedIdentities, err := FindIdentitiesByUserID(ts.db, u.ID)
	require.NoError(ts.T(), err)
	for _, identity := range updatedIdentities {
		require.Empty(ts.T(), identity.IdentityData)
	}
}

func (ts *IdentityTestSuite) createUserWithEmail(email string) *User {
	id := uuid.Must(uuid.FromString("123e4567-e89b-12d3-a456-426655440000"))
	user, err := NewUser("", email, "secret", "test", nil, id, uuid.Nil)
	require.NoError(ts.T(), err)

	err = ts.db.Create(user, "project_id", "organization_role")
	require.NoError(ts.T(), err)

	return user
}

func (ts *IdentityTestSuite) createUserWithIdentity(email string) *User {
	id := uuid.Must(uuid.FromString("123e4567-e89b-12d3-a456-426655440000"))
	user, err := NewUser("", email, "secret", "test", nil, id, uuid.Nil)
	require.NoError(ts.T(), err)

	err = ts.db.Create(user, "project_id", "organization_role")
	require.NoError(ts.T(), err)

	identityData := map[string]interface{}{
		"sub":   uuid.Nil.String(),
		"name":  "test",
		"email": email,
	}
	require.NoError(ts.T(), err)

	identity, err := NewIdentity(user, "email", identityData)
	require.NoError(ts.T(), err)

	err = ts.db.Create(identity, "project_id")
	require.NoError(ts.T(), err)

	return user
}
