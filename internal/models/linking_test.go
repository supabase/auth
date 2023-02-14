package models

import (
	"testing"

	"github.com/supabase/gotrue/internal/conf"
	"github.com/supabase/gotrue/internal/storage"
	"github.com/supabase/gotrue/internal/storage/test"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type AccountLinkingTestSuite struct {
	suite.Suite

	db *storage.Connection
}

func (ts *AccountLinkingTestSuite) SetupTest() {
	TruncateAll(ts.db)
}

func TestAccountLinking(t *testing.T) {
	globalConfig, err := conf.LoadGlobal(modelsTestConfig)
	require.NoError(t, err)

	conn, err := test.SetupDBConnection(globalConfig)
	require.NoError(t, err)

	ts := &AccountLinkingTestSuite{
		db: conn,
	}
	defer ts.db.Close()

	suite.Run(t, ts)
}

func (ts *AccountLinkingTestSuite) TestCreateAccountDecisionNoAccounts() {
	// when there are no accounts in the system -- conventional provider
	decision, err := DetermineAccountLinking(ts.db, "provider", "abcdefgh", []string{"test@example.com"})
	require.NoError(ts.T(), err)

	require.Equal(ts.T(), decision.Decision, CreateAccount)

	// when there are no accounts in the system -- SSO provider
	decision, err = DetermineAccountLinking(ts.db, "sso:f06f9e3d-ff92-4c47-a179-7acf1fda6387", "abcdefgh", []string{"test@example.com"})
	require.NoError(ts.T(), err)

	require.Equal(ts.T(), decision.Decision, CreateAccount)
}

func (ts *AccountLinkingTestSuite) TestCreateAccountDecisionWithAccounts() {
	userA, err := NewUser("", "test@example.com", "", "authenticated", nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(userA))
	identityA, err := NewIdentity(userA, "provider", map[string]interface{}{
		"sub":   userA.ID.String(),
		"email": "test@example.com",
	})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(identityA))

	userB, err := NewUser("", "test@samltest.id", "", "authenticated", nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(userB))

	identityB, err := NewIdentity(userB, "sso:f06f9e3d-ff92-4c47-a179-7acf1fda6387", map[string]interface{}{
		"sub":   userB.ID.String(),
		"email": "test@samltest.id",
	})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(identityB))

	// when there are no accounts in the system -- conventional provider
	decision, err := DetermineAccountLinking(ts.db, "provider", "abcdefgh", []string{"other@example.com"})
	require.NoError(ts.T(), err)

	require.Equal(ts.T(), decision.Decision, CreateAccount)

	// when looking for an email that doesn't exist in the SSO linking domain
	decision, err = DetermineAccountLinking(ts.db, "sso:f06f9e3d-ff92-4c47-a179-7acf1fda6387", "abcdefgh", []string{"other@samltest.id"})
	require.NoError(ts.T(), err)

	require.Equal(ts.T(), decision.Decision, CreateAccount)

	// when looking for an email that doesn't exist at all
	decision, err = DetermineAccountLinking(ts.db, "sso:f06f9e3d-ff92-4c47-a179-7acf1fda6387", "abcdefgh", []string{"other@samltest.id"})
	require.NoError(ts.T(), err)

	require.Equal(ts.T(), decision.Decision, CreateAccount)

	// when looking for an email that doesn't exist in the SSO linking domain
	decision, err = DetermineAccountLinking(ts.db, "sso:f06f9e3d-ff92-4c47-a179-7acf1fda6387", "abcdefgh", []string{"text@example.com"})
	require.NoError(ts.T(), err)

	require.Equal(ts.T(), decision.Decision, CreateAccount)
}

func (ts *AccountLinkingTestSuite) TestAccountExists() {
	userA, err := NewUser("", "test@example.com", "", "authenticated", nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(userA))
	identityA, err := NewIdentity(userA, "provider", map[string]interface{}{
		"sub":   userA.ID.String(),
		"email": "test@example.com",
	})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(identityA))

	decision, err := DetermineAccountLinking(ts.db, "provider", userA.ID.String(), []string{"test@example.com"})
	require.NoError(ts.T(), err)

	require.Equal(ts.T(), decision.Decision, AccountExists)
	require.Equal(ts.T(), decision.User.ID, userA.ID)
}

func (ts *AccountLinkingTestSuite) TestLinkAccountExists() {
	userA, err := NewUser("", "test@example.com", "", "authenticated", nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(userA))
	identityA, err := NewIdentity(userA, "provider", map[string]interface{}{
		"sub":   userA.ID.String(),
		"email": "test@example.com",
	})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(identityA))

	// link decision because the below described identity is in the default linking domain but uses "other-provider" instead of "provder"
	decision, err := DetermineAccountLinking(ts.db, "other-provider", userA.ID.String(), []string{"test@example.com"})
	require.NoError(ts.T(), err)

	require.Equal(ts.T(), decision.Decision, LinkAccount)

	userB, err := NewUser("", "test@samltest.id", "", "authenticated", nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(userB))

	identityB, err := NewIdentity(userB, "sso:f06f9e3d-ff92-4c47-a179-7acf1fda6387", map[string]interface{}{
		"sub":   userB.ID.String(),
		"email": "test@samltest.id",
	})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(identityB))

	// no link decision because the SSO linking domain is scoped to the provider unique ID
	decision, err = DetermineAccountLinking(ts.db, "sso:f06f9e3d-ff92-4c47-a179-7acf1fda6387", userB.ID.String(), []string{"test@samltest.id"})
	require.NoError(ts.T(), err)

	require.NotEqual(ts.T(), decision.Decision, LinkAccount)
}

func (ts *AccountLinkingTestSuite) TestMultipleAccounts() {
	userA, err := NewUser("", "test@example.com", "", "authenticated", nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(userA))
	identityA, err := NewIdentity(userA, "provider", map[string]interface{}{
		"sub":   userA.ID.String(),
		"email": "test@example.com",
	})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(identityA))

	userB, err := NewUser("", "test-b@example.com", "", "authenticated", nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(userB))
	identityB, err := NewIdentity(userB, "provider", map[string]interface{}{
		"sub":   userB.ID.String(),
		"email": "test@example.com", // intentionally same as userA
	})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(identityB))

	// decision is multiple accounts because there are two distinct
	// identities in the same "default" linking domain with the same email
	// address pointing to two different user accounts
	decision, err := DetermineAccountLinking(ts.db, "provider", "abcdefgh", []string{"test@example.com"})
	require.NoError(ts.T(), err)

	require.Equal(ts.T(), decision.Decision, MultipleAccounts)
}
