package models

import (
	"context"
	"fmt"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/crypto"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/storage/test"
	"golang.org/x/crypto/bcrypt"
)

const modelsTestConfig = "../../hack/test.env"

func init() {
	crypto.PasswordHashCost = crypto.QuickHashCost
}

type UserTestSuite struct {
	suite.Suite
	db *storage.Connection
}

func (ts *UserTestSuite) SetupTest() {
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

func TestUser(t *testing.T) {
	globalConfig, err := conf.LoadGlobal(modelsTestConfig)
	require.NoError(t, err)

	conn, err := test.SetupDBConnection(globalConfig)
	require.NoError(t, err)

	ts := &UserTestSuite{
		db: conn,
	}
	defer ts.db.Close()

	suite.Run(t, ts)
}

func (ts *UserTestSuite) TestUpdateAppMetadata() {

	id := uuid.Must(uuid.FromString("123e4567-e89b-12d3-a456-426655440000"))
	u, err := NewUser("", "", "", "", nil, id, uuid.Nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), u.UpdateAppMetaData(ts.db, make(map[string]interface{})))

	require.NotNil(ts.T(), u.AppMetaData)

	require.NoError(ts.T(), u.UpdateAppMetaData(ts.db, map[string]interface{}{
		"foo": "bar",
	}))

	require.Equal(ts.T(), "bar", u.AppMetaData["foo"])
	require.NoError(ts.T(), u.UpdateAppMetaData(ts.db, map[string]interface{}{
		"foo": nil,
	}))
	require.Len(ts.T(), u.AppMetaData, 0)
	require.Equal(ts.T(), nil, u.AppMetaData["foo"])
}

func (ts *UserTestSuite) TestUpdateUserMetadata() {
	id := uuid.Must(uuid.FromString("123e4567-e89b-12d3-a456-426655440000"))
	u, err := NewUser("", "", "", "", nil, id, uuid.Nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), u.UpdateUserMetaData(ts.db, make(map[string]interface{})))

	require.NotNil(ts.T(), u.UserMetaData)

	require.NoError(ts.T(), u.UpdateUserMetaData(ts.db, map[string]interface{}{
		"foo": "bar",
	}))

	require.Equal(ts.T(), "bar", u.UserMetaData["foo"])
	require.NoError(ts.T(), u.UpdateUserMetaData(ts.db, map[string]interface{}{
		"foo": nil,
	}))
	require.Len(ts.T(), u.UserMetaData, 0)
	require.Equal(ts.T(), nil, u.UserMetaData["foo"])
}

func (ts *UserTestSuite) TestFindUserByConfirmationToken() {
	id := uuid.Must(uuid.FromString("123e4567-e89b-12d3-a456-426655440000"))
	u := ts.createUser(id)
	tokenHash := "test_confirmation_token"
	require.NoError(ts.T(), CreateOneTimeToken(ts.db, u.ID, "relates_to not used", tokenHash, ConfirmationToken))

	n, err := FindUserByConfirmationToken(ts.db, tokenHash)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), u.ID, n.ID)
}

func (ts *UserTestSuite) TestFindUserByEmailAndAudience() {
	id := uuid.Must(uuid.FromString("123e4567-e89b-12d3-a456-426655440000"))
	u := ts.createUser(id)

	n, err := FindUserByEmailAndAudience(ts.db, u.GetEmail(), "test", id, uuid.Nil)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), u.ID, n.ID)

	_, err = FindUserByEmailAndAudience(ts.db, u.GetEmail(), "invalid", id, uuid.Nil)
	require.EqualError(ts.T(), err, UserNotFoundError{}.Error())
}

func (ts *UserTestSuite) TestFindUsersInAudience() {
	id := uuid.Must(uuid.FromString("123e4567-e89b-12d3-a456-426655440000"))
	u := ts.createUser(id)

	n, err := FindUsersInAudience(ts.db, u.Aud, nil, nil, "", id, uuid.Nil)
	require.NoError(ts.T(), err)
	require.Len(ts.T(), n, 1)

	p := Pagination{
		Page:    1,
		PerPage: 50,
	}
	n, err = FindUsersInAudience(ts.db, u.Aud, &p, nil, "", id, uuid.Nil)
	require.NoError(ts.T(), err)
	require.Len(ts.T(), n, 1)
	assert.Equal(ts.T(), uint64(1), p.Count)

	sp := &SortParams{
		Fields: []SortField{
			{Name: "created_at", Dir: Descending},
		},
	}
	n, err = FindUsersInAudience(ts.db, u.Aud, nil, sp, "", id, uuid.Nil)
	require.NoError(ts.T(), err)
	require.Len(ts.T(), n, 1)
}

func (ts *UserTestSuite) TestFindUserByID() {
	id := uuid.Must(uuid.FromString("123e4567-e89b-12d3-a456-426655440000"))
	u := ts.createUser(id)

	n, err := FindUserByID(ts.db, u.ID)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), u.ID, n.ID)
}

func (ts *UserTestSuite) TestFindUserByRecoveryToken() {
	id := uuid.Must(uuid.FromString("123e4567-e89b-12d3-a456-426655440000"))
	u := ts.createUser(id)
	tokenHash := "test_recovery_token"
	require.NoError(ts.T(), CreateOneTimeToken(ts.db, u.ID, "relates_to not used", tokenHash, RecoveryToken))

	n, err := FindUserByRecoveryToken(ts.db, tokenHash)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), u.ID, n.ID)
}

func (ts *UserTestSuite) TestFindUserWithRefreshToken() {
	id := uuid.Must(uuid.FromString("123e4567-e89b-12d3-a456-426655440000"))
	u := ts.createUser(id)
	r, err := GrantAuthenticatedUser(ts.db, u, GrantParams{})
	require.NoError(ts.T(), err)

	n, nr, s, err := FindUserWithRefreshToken(ts.db, r.Token, true /* forUpdate */)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), r.ID, nr.ID)
	require.Equal(ts.T(), u.ID, n.ID)
	require.NotNil(ts.T(), s)
	require.Equal(ts.T(), *r.SessionId, s.ID)
}

func (ts *UserTestSuite) TestIsDuplicatedEmail() {
	id := uuid.Must(uuid.FromString("123e4567-e89b-12d3-a456-426655440000"))
	_ = ts.createUserWithEmail("david.calavera@netlify.com", id)

	e, err := IsDuplicatedEmail(ts.db, "david.calavera@netlify.com", "test", nil, id, uuid.Nil)
	require.NoError(ts.T(), err)
	require.NotNil(ts.T(), e, "expected email to be duplicated")

	e, err = IsDuplicatedEmail(ts.db, "davidcalavera@netlify.com", "test", nil, id, uuid.Nil)
	require.NoError(ts.T(), err)
	require.Nil(ts.T(), e, "expected email to not be duplicated", id, nil)

	e, err = IsDuplicatedEmail(ts.db, "david@netlify.com", "test", nil, id, uuid.Nil)
	require.NoError(ts.T(), err)
	require.Nil(ts.T(), e, "expected same email to not be duplicated", nil)

	e, err = IsDuplicatedEmail(ts.db, "david.calavera@netlify.com", "other-aud", nil, id, uuid.Nil)
	require.NoError(ts.T(), err)
	require.Nil(ts.T(), e, "expected same email to not be duplicated")
}

func (ts *UserTestSuite) createUser(id uuid.UUID) *User {
	return ts.createUserWithEmail("david@netlify.com", id)
}

func (ts *UserTestSuite) createUserWithEmail(email string, id uuid.UUID) *User {
	user, err := NewUser("", email, "secret", "test", nil, id, uuid.Nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(user, "project_id", "organization_role"))

	identity, err := NewIdentity(user, "email", map[string]interface{}{
		"sub":   user.ID.String(),
		"email": email,
	})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(identity, "project_id"))

	return user
}

func (ts *UserTestSuite) TestRemoveUnconfirmedIdentities() {
	id := uuid.Must(uuid.FromString("123e4567-e89b-12d3-a456-426655440000"))
	user, err := NewUser("+29382983298", "someone@example.com", "abcdefgh", "authenticated", nil, id, uuid.Nil)
	require.NoError(ts.T(), err)

	user.AppMetaData = map[string]interface{}{
		"provider":  "email",
		"providers": []string{"email", "phone", "twitter"},
	}

	require.NoError(ts.T(), ts.db.Create(user, "project_id", "organization_role"))

	idEmail, err := NewIdentity(user, "email", map[string]interface{}{
		"sub": "someone@example.com",
	})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(idEmail, "project_id"))

	idPhone, err := NewIdentity(user, "phone", map[string]interface{}{
		"sub": "+29382983298",
	})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(idPhone, "project_id"))

	idTwitter, err := NewIdentity(user, "twitter", map[string]interface{}{
		"sub": "test_twitter_user_id",
	})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(idTwitter, "project_id"))

	user.Identities = append(user.Identities, *idEmail, *idPhone, *idTwitter)

	// reload the user
	require.NoError(ts.T(), ts.db.Load(user))

	require.False(ts.T(), user.IsConfirmed(), "user's email must not be confirmed")

	require.NoError(ts.T(), user.RemoveUnconfirmedIdentities(ts.db, idTwitter))

	// reload the user to check that identities are deleted from the db too
	require.NoError(ts.T(), ts.db.Load(user))
	require.Empty(ts.T(), user.EncryptedPassword, "password still remains in user")

	require.Len(ts.T(), user.Identities, 1, "only one identity must be remaining")
	require.Equal(ts.T(), idTwitter.ID, user.Identities[0].ID, "remaining identity is not the expected one")

	require.NotNil(ts.T(), user.AppMetaData)
	require.Equal(ts.T(), user.AppMetaData["provider"], "twitter")
	require.Equal(ts.T(), user.AppMetaData["providers"], []string{"twitter"})
}

func (ts *UserTestSuite) TestConfirmEmailChange() {
	id := uuid.Must(uuid.FromString("123e4567-e89b-12d3-a456-426655440000"))
	user, err := NewUser("", "test@example.com", "", "authenticated", nil, id, uuid.Nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(user, "project_id", "organization_role"))

	identity, err := NewIdentity(user, "email", map[string]interface{}{
		"sub":   user.ID.String(),
		"email": "test@example.com",
	})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(identity, "project_id"))

	user.EmailChange = "new@example.com"
	require.NoError(ts.T(), ts.db.UpdateOnly(user, "email_change"))

	require.NoError(ts.T(), user.ConfirmEmailChange(ts.db, 0))

	require.NoError(ts.T(), ts.db.Eager().Load(user))
	identity, err = FindIdentityByIdAndProvider(ts.db, user.ID.String(), "email", user.OrganizationID.UUID, user.ProjectID.UUID)
	require.NoError(ts.T(), err)

	require.Equal(ts.T(), user.Email, storage.NullString("new@example.com"))
	require.Equal(ts.T(), user.EmailChange, "")

	require.NotNil(ts.T(), identity.IdentityData)
	require.Equal(ts.T(), identity.IdentityData["email"], "new@example.com")
}

func (ts *UserTestSuite) TestConfirmPhoneChange() {
	id := uuid.Must(uuid.FromString("123e4567-e89b-12d3-a456-426655440000"))
	user, err := NewUser("123456789", "", "", "authenticated", nil, id, uuid.Nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(user, "project_id", "organization_role"))

	identity, err := NewIdentity(user, "phone", map[string]interface{}{
		"sub":   user.ID.String(),
		"phone": "123456789",
	})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(identity, "project_id"))

	user.PhoneChange = "987654321"
	require.NoError(ts.T(), ts.db.UpdateOnly(user, "phone_change"))

	require.NoError(ts.T(), user.ConfirmPhoneChange(ts.db))

	require.NoError(ts.T(), ts.db.Eager().Load(user))
	identity, err = FindIdentityByIdAndProvider(ts.db, user.ID.String(), "phone", user.OrganizationID.UUID, user.ProjectID.UUID)
	require.NoError(ts.T(), err)

	require.Equal(ts.T(), user.Phone, storage.NullString("987654321"))
	require.Equal(ts.T(), user.PhoneChange, "")

	require.NotNil(ts.T(), identity.IdentityData)
	require.Equal(ts.T(), identity.IdentityData["phone"], "987654321")
}

func (ts *UserTestSuite) TestUpdateUserEmailSuccess() {
	id := uuid.Must(uuid.FromString("123e4567-e89b-12d3-a456-426655440000"))
	userA, err := NewUser("", "foo@example.com", "", "authenticated", nil, id, uuid.Nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(userA, "project_id", "organization_role"))

	primaryIdentity, err := NewIdentity(userA, "email", map[string]interface{}{
		"sub":   userA.ID.String(),
		"email": "foo@example.com",
	})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(primaryIdentity, "project_id"))

	secondaryIdentity, err := NewIdentity(userA, "google", map[string]interface{}{
		"sub":   userA.ID.String(),
		"email": "bar@example.com",
	})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(secondaryIdentity, "project_id"))

	// UpdateUserEmail should not do anything and the user's email should still use the primaryIdentity
	require.NoError(ts.T(), userA.UpdateUserEmailFromIdentities(ts.db))
	require.Equal(ts.T(), primaryIdentity.GetEmail(), userA.GetEmail())

	// remove primary identity
	require.NoError(ts.T(), ts.db.Destroy(primaryIdentity))

	// UpdateUserEmail should update the user to use the secondary identity's email
	require.NoError(ts.T(), userA.UpdateUserEmailFromIdentities(ts.db))
	require.Equal(ts.T(), secondaryIdentity.GetEmail(), userA.GetEmail())
}

func (ts *UserTestSuite) TestUpdateUserEmailFailure() {
	id := uuid.Must(uuid.FromString("123e4567-e89b-12d3-a456-426655440000"))
	userA, err := NewUser("", "foo@example.com", "", "authenticated", nil, id, uuid.Nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(userA, "project_id", "organization_role"))

	primaryIdentity, err := NewIdentity(userA, "email", map[string]interface{}{
		"sub":   userA.ID.String(),
		"email": "foo@example.com",
	})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(primaryIdentity, "project_id"))

	secondaryIdentity, err := NewIdentity(userA, "google", map[string]interface{}{
		"sub":   userA.ID.String(),
		"email": "bar@example.com",
	})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(secondaryIdentity, "project_id"))

	userB, err := NewUser("", "bar@example.com", "", "authenticated", nil, id, uuid.Nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(userB, "project_id", "organization_role"))

	// remove primary identity
	require.NoError(ts.T(), ts.db.Destroy(primaryIdentity))

	// UpdateUserEmail should fail with the email unique constraint violation error
	//  since userB is using the secondary identity's email
	require.ErrorIs(ts.T(), userA.UpdateUserEmailFromIdentities(ts.db), UserEmailUniqueConflictError{})
	require.Equal(ts.T(), primaryIdentity.GetEmail(), userA.GetEmail())
}

func (ts *UserTestSuite) TestNewUserWithPasswordHashSuccess() {
	cases := []struct {
		desc string
		hash string
	}{
		{
			desc: "Valid bcrypt hash",
			hash: "$2y$10$SXEz2HeT8PUIGQXo9yeUIem8KzNxgG0d7o/.eGj2rj8KbRgAuRVlq",
		},
		{
			desc: "Valid argon2i hash",
			hash: "$argon2i$v=19$m=16,t=2,p=1$bGJRWThNOHJJTVBSdHl2dQ$NfEnUOuUpb7F2fQkgFUG4g",
		},
		{
			desc: "Valid argon2id hash",
			hash: "$argon2id$v=19$m=32,t=3,p=2$SFVpOWJ0eXhjRzVkdGN1RQ$RXnb8rh7LaDcn07xsssqqulZYXOM/EUCEFMVcAcyYVk",
		},
		{
			desc: "Valid Firebase scrypt hash",
			hash: "$fbscrypt$v=1,n=14,r=8,p=1,ss=Bw==,sk=ou9tdYTGyYm8kuR6Dt0Bp0kDuAYoXrK16mbZO4yGwAn3oLspjnN0/c41v8xZnO1n14J3MjKj1b2g6AUCAlFwMw==$C0sHCg9ek77hsg==$ZGlmZmVyZW50aGFzaA==",
		},
	}

	for _, c := range cases {
		ts.Run(c.desc, func() {
			id := uuid.Must(uuid.FromString("123e4567-e89b-12d3-a456-426655440000"))
			u, err := NewUserWithPasswordHash("", "", c.hash, "", nil, id, uuid.Nil)
			require.NoError(ts.T(), err)
			require.NotNil(ts.T(), u)
		})
	}
}

func (ts *UserTestSuite) TestNewUserWithPasswordHashFailure() {
	cases := []struct {
		desc string
		hash string
	}{
		{
			desc: "Invalid argon2i hash",
			hash: "$argon2id$test",
		},
		{
			desc: "Invalid bcrypt hash",
			hash: "plaintest_password",
		},
		{
			desc: "Invalid scrypt hash",
			hash: "$fbscrypt$invalid",
		},
	}

	for _, c := range cases {
		ts.Run(c.desc, func() {
			id := uuid.Must(uuid.FromString("123e4567-e89b-12d3-a456-426655440000"))
			u, err := NewUserWithPasswordHash("", "", c.hash, "", nil, id, uuid.Nil)
			require.Error(ts.T(), err)
			require.Nil(ts.T(), u)
		})
	}
}

func (ts *UserTestSuite) TestAuthenticate() {
	// every case uses "test" as the password
	cases := []struct {
		desc             string
		hash             string
		expectedHashCost int
	}{
		{
			desc:             "Invalid bcrypt hash cost of 11",
			hash:             "$2y$11$4lH57PU7bGATpRcx93vIoObH3qDmft/pytbOzDG9/1WsyNmN5u4di",
			expectedHashCost: bcrypt.MinCost,
		},
		{
			desc:             "Valid bcrypt hash cost of 10",
			hash:             "$2y$10$va66S4MxFrH6G6L7BzYl0.QgcYgvSr/F92gc.3botlz7bG4p/g/1i",
			expectedHashCost: bcrypt.DefaultCost,
		},
	}

	for _, c := range cases {
		ts.Run(c.desc, func() {
			id := uuid.Must(uuid.FromString("123e4567-e89b-12d3-a456-426655440000"))
			u, err := NewUserWithPasswordHash("", "", c.hash, "", nil, id, uuid.Nil)
			require.NoError(ts.T(), err)
			require.NoError(ts.T(), ts.db.Create(u, "project_id", "organization_role"))
			require.NotNil(ts.T(), u)

			isAuthenticated, _, err := u.Authenticate(context.Background(), ts.db, "test", nil, false, "")
			require.NoError(ts.T(), err)
			require.True(ts.T(), isAuthenticated)

			// check hash cost
			hashCost, err := bcrypt.Cost([]byte(*u.EncryptedPassword))
			require.NoError(ts.T(), err)
			require.Equal(ts.T(), c.expectedHashCost, hashCost)
		})
	}
}

func (ts *UserTestSuite) TestCreateMultipleAdminUsersWithSameEmailDifferentProjects() {
	projectID1 := uuid.Must(uuid.NewV4())
	projectID2 := uuid.Must(uuid.NewV4())

	// Create project 1
	if err := ts.db.RawQuery(fmt.Sprintf("INSERT INTO auth.projects (id, name) VALUES ('%s', 'test_project_1')", projectID1)).Exec(); err != nil {
		panic(err)
	}

	// Create project 2
	if err := ts.db.RawQuery(fmt.Sprintf("INSERT INTO auth.projects (id, name) VALUES ('%s', 'test_project_2')", projectID2)).Exec(); err != nil {
		panic(err)
	}

	// Create user 1
	user1, err := NewUser("", "example@example.com", "test", "", nil, uuid.Nil, projectID1)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(user1, "organization_id", "organization_role"))

	// Create user 2
	user2, err := NewUser("", "example@example.com", "test", "", nil, uuid.Nil, projectID2)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(user2, "organization_id", "organization_role"))

	// Check if user 1 and user 2 have the same email
	require.Equal(ts.T(), user1.Email, user2.Email)
}

func (ts *UserTestSuite) TestCreateMultipleAdminUsersWithSameEmailSameProject() {
	projectID := uuid.Must(uuid.NewV4())

	// Create project
	if err := ts.db.RawQuery(fmt.Sprintf("INSERT INTO auth.projects (id, name) VALUES ('%s', 'test_project')", projectID)).Exec(); err != nil {
		panic(err)
	}

	// Create user 1
	user1, err := NewUser("", "example@example.com", "test", "", nil, uuid.Nil, projectID)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(user1, "organization_id", "organization_role"))

	// Create user 2 -> should fail
	user2, err := NewUser("", "example@example.com", "test", "", nil, uuid.Nil, projectID)
	require.NoError(ts.T(), err)
	require.Error(ts.T(), ts.db.Create(user2, "organization_id", "organization_role"))

	// Check if user 1 and user 2 have the same email
	require.Equal(ts.T(), user1.Email, user2.Email)
}

func (ts *UserTestSuite) TestCreateMultpleUsersWithSameEmailDifferentOrganizations() {
	projectID := uuid.Must(uuid.NewV4())

	// Create project
	if err := ts.db.RawQuery(fmt.Sprintf("INSERT INTO auth.projects (id, name) VALUES ('%s', 'test_project')", projectID)).Exec(); err != nil {
		panic(err)
	}

	// create admin user for organization 1
	adminUser1, err := NewUser("", "admin@example1.com", "test", "", nil, uuid.Nil, projectID)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(adminUser1, "organization_id", "organization_role"))

	// Create organization 1
	organizationID1 := uuid.Must(uuid.NewV4())
	if err := ts.db.RawQuery(fmt.Sprintf("INSERT INTO auth.organizations (id, name, project_id, admin_id) VALUES ('%s', 'test_organization_1', '%s', '%s')", organizationID1, projectID, adminUser1.ID)).Exec(); err != nil {
		panic(err)
	}

	// Create admin user for organization 2
	adminUser2, err := NewUser("", "admin@example2.com", "test", "", nil, uuid.Nil, projectID)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(adminUser2, "organization_id", "organization_role"))

	// Create organization 2
	organizationID2 := uuid.Must(uuid.NewV4())
	if err := ts.db.RawQuery(fmt.Sprintf("INSERT INTO auth.organizations (id, name, project_id, admin_id) VALUES ('%s', 'test_organization_2', '%s', '%s')", organizationID2, projectID, adminUser2.ID)).Exec(); err != nil {
		panic(err)
	}

	// Create user 1
	user1, err := NewUser("", "example@example.com", "test", "", nil, organizationID1, uuid.Nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(user1, "project_id", "organization_role"))

	// Create user 2
	user2, err := NewUser("", "example@example.com", "test", "", nil, organizationID2, uuid.Nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(user2, "project_id", "organization_role"))

	// Check if user 1 and user 2 have the same email
	require.Equal(ts.T(), user1.Email, user2.Email)
}

func (ts *UserTestSuite) TestCreateMultpleUsersWithSameEmailSameOrganization() {
	projectID := uuid.Must(uuid.NewV4())

	// Create project
	if err := ts.db.RawQuery(fmt.Sprintf("INSERT INTO auth.projects (id, name) VALUES ('%s', 'test_project')", projectID)).Exec(); err != nil {
		panic(err)
	}

	// create admin user
	adminUser, err := NewUser("", "admin@example.com", "test", "", nil, uuid.Nil, projectID)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(adminUser, "organization_id", "organization_role"))

	// Create organization
	organizationID := uuid.Must(uuid.NewV4())
	if err := ts.db.RawQuery(fmt.Sprintf("INSERT INTO auth.organizations (id, name, project_id, admin_id) VALUES ('%s', 'test_organization', '%s', '%s')", organizationID, projectID, adminUser.ID)).Exec(); err != nil {
		panic(err)
	}

	// Create user 1
	user1, err := NewUser("", "user@example.com", "test", "", nil, organizationID, uuid.Nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(user1, "project_id", "organization_role"))

	// Create user 2 -> should fail
	user2, err := NewUser("", "user@example.com", "test", "", nil, organizationID, uuid.Nil)
	require.NoError(ts.T(), err)
	require.Error(ts.T(), ts.db.Create(user2, "project_id", "organization_role"))

	// Check if user 1 and user 2 have the same email
	require.Equal(ts.T(), user1.Email, user2.Email)
}

func (ts *UserTestSuite) TestCreateUserAndSetProjectID() {
	projectID := uuid.Must(uuid.NewV4())

	// Create project
	if err := ts.db.RawQuery(fmt.Sprintf("INSERT INTO auth.projects (id, name) VALUES ('%s', 'test_project')", projectID)).Exec(); err != nil {
		panic(err)
	}

	// Create user
	user, err := NewUser("", "admin@example.com", "test", "", nil, uuid.Nil, projectID)

	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(user, "organization_id", "organization_role", "organization_role"))

	// Create organization
	organizationID := uuid.Must(uuid.NewV4())
	if err := ts.db.RawQuery(fmt.Sprintf("INSERT INTO auth.organizations (id, name, project_id, admin_id) VALUES ('%s', 'test_organization', '%s', '%s')", organizationID, projectID, user.ID)).Exec(); err != nil {
		panic(err)
	}

	// Set project ID for user, should fail
	user.ProjectID = uuid.NullUUID{UUID: uuid.Must(uuid.NewV4()), Valid: true}
	require.Error(ts.T(), ts.db.Update(user))
}
