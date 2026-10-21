package models

import (
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/conf/confload"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/storage/test"
)

type IdentityTestSuite struct {
	suite.Suite
	db *storage.Connection
}

func (ts *IdentityTestSuite) SetupTest() {
	TruncateAll(ts.db)
}

func TestIdentity(t *testing.T) {
	globalConfig, err := confload.LoadGlobal(modelsTestConfig)
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

	ts.Run("Test create identity with string email", func() {
		identityData := map[string]interface{}{"sub": uuid.Nil.String(), "email": "test@supabase.io"}
		identity, err := NewIdentity(u, "email", identityData)
		require.NoError(ts.T(), err)
		require.Equal(ts.T(), "test@supabase.io", identity.GetEmail())
	})

	// A phone signup omits the (empty) email claim, so a user-supplied
	// `data.email` can reach identityData as a non-string value. NewIdentity
	// must not panic on it. Regression test for supabase/auth#2268.
	ts.Run("Test create identity with non-string email does not panic", func() {
		for _, email := range []interface{}{nil, 123, true, map[string]interface{}{}} {
			identityData := map[string]interface{}{"sub": uuid.Nil.String(), "email": email}
			identity, err := NewIdentity(u, "phone", identityData)
			require.NoError(ts.T(), err)
			require.Empty(ts.T(), identity.GetEmail(), "email should be unset for non-string value %#v", email)
		}
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
	user, err := NewUser("", email, "secret", "test", nil)
	require.NoError(ts.T(), err)

	err = ts.db.Create(user)
	require.NoError(ts.T(), err)

	return user
}

func (ts *IdentityTestSuite) createUserWithIdentity(email string) *User {
	user, err := NewUser("", email, "secret", "test", nil)
	require.NoError(ts.T(), err)

	err = ts.db.Create(user)
	require.NoError(ts.T(), err)

	identityData := map[string]interface{}{
		"sub":   uuid.Nil.String(),
		"name":  "test",
		"email": email,
	}
	require.NoError(ts.T(), err)

	identity, err := NewIdentity(user, "email", identityData)
	require.NoError(ts.T(), err)

	err = ts.db.Create(identity)
	require.NoError(ts.T(), err)

	return user
}
