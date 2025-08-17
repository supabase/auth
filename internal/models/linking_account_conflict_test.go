package models

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/api/provider"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/storage"
)

type AccountConflictTestSuite struct {
	suite.Suite
	db     *storage.Connection
	config *conf.GlobalConfiguration
}

func TestAccountConflict(t *testing.T) {
	globalConfig, err := conf.LoadGlobal("../../hack/test.env")
	require.NoError(t, err)

	conn, err := storage.Dial(globalConfig)
	require.NoError(t, err)

	ts := &AccountConflictTestSuite{
		db:     conn,
		config: globalConfig,
	}
	defer conn.Close()

	suite.Run(t, ts)
}

func (ts *AccountConflictTestSuite) SetupTest() {
	TruncateAll(ts.db)
}

// TestEmailPasswordThenSAMLSSOConflict reproduces the exact issue described:
// 1. User creates account with email/password (user@example.com)
// 2. User tries to login with SAML SSO using same email
// 3. System fails to link the accounts and tries to create a new account instead
func (ts *AccountConflictTestSuite) TestEmailPasswordThenSAMLSSOConflict() {
	email := "user@example.com"
	aud := ts.config.JWT.Aud

	// Step 1: Create a user with email/password authentication
	user, err := NewUser("", email, "password123", aud, nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(user))

	// Create the email identity for the user (this happens during signup)
	emailIdentity, err := NewIdentity(user, "email", map[string]interface{}{
		"sub":   user.ID.String(),
		"email": email,
	})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(emailIdentity))

	// Verify user exists with email provider
	require.Equal(ts.T(), email, user.GetEmail())
	require.False(ts.T(), user.IsSSOUser)

	// Step 2: Now try SAML SSO login with the same email
	samlProviderType := "sso:12345678-1234-5678-9abc-123456789012" // Mock SSO provider ID
	samlSubject := "saml_user_id_from_entra_id"

	samlEmails := []provider.Email{
		{
			Email:    email,
			Verified: true,
			Primary:  true,
		},
	}

	// Step 3: This should link to the existing account
	decision, err := DetermineAccountLinking(ts.db, ts.config, samlEmails, aud, samlProviderType, samlSubject)
	require.NoError(ts.T(), err)

	// FIXED: Now correctly returns LinkAccount and finds the existing user
	require.Equal(ts.T(), LinkAccount, decision.Decision, "Should link to existing email/password account")
	require.Equal(ts.T(), user.ID, decision.User.ID, "Should find the existing user")
	require.Equal(ts.T(), samlProviderType, decision.LinkingDomain)
	require.Equal(ts.T(), email, decision.CandidateEmail.Email)
}

// TestSAMLSSOThenEmailPasswordConflict tests the reverse scenario
func (ts *AccountConflictTestSuite) TestSAMLSSOThenEmailPasswordConflict() {
	email := "user@example.com"
	aud := ts.config.JWT.Aud

	// Step 1: Create a user via SAML SSO first
	ssoUser, err := NewUser("", email, "", aud, nil)
	require.NoError(ts.T(), err)
	ssoUser.IsSSOUser = true
	require.NoError(ts.T(), ts.db.Create(ssoUser))

	// Create the SAML identity for the user
	samlProviderType := "sso:12345678-1234-5678-9abc-123456789012"
	samlIdentity, err := NewIdentity(ssoUser, samlProviderType, map[string]interface{}{
		"sub":   "saml_user_id_from_entra_id",
		"email": email,
	})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(samlIdentity))

	// Step 2: Now try email/password signup with the same email
	emailProviderType := "email"
	emailSubject := ssoUser.ID.String() // For email provider, subject is usually the user ID

	emailEmails := []provider.Email{
		{
			Email:    email,
			Verified: true,
			Primary:  true,
		},
	}

	// Step 3: Check account linking decision
	decision, err := DetermineAccountLinking(ts.db, ts.config, emailEmails, aud, emailProviderType, emailSubject)
	require.NoError(ts.T(), err)

	// This scenario works correctly because email providers DO check for similarUsers
	// but they exclude SSO users (line 119 in linking.go: "is_sso_user = false")
	// So it will create a new account instead of linking
	require.Equal(ts.T(), CreateAccount, decision.Decision)
	require.Equal(ts.T(), "default", decision.LinkingDomain)
	require.Equal(ts.T(), email, decision.CandidateEmail.Email)
}

// TestMultipleEmailPasswordAccountsConflict tests what happens when there are
// multiple email/password accounts with the same email (which shouldn't happen)
func (ts *AccountConflictTestSuite) TestMultipleEmailPasswordAccountsConflict() {
	email := "user@example.com"
	aud := ts.config.JWT.Aud

	// Create first user with email/password
	user1, err := NewUser("", email, "password123", aud, nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(user1))

	identity1, err := NewIdentity(user1, "email", map[string]interface{}{
		"sub":   user1.ID.String(),
		"email": email,
	})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(identity1))

	// Create second user with different provider but same email - use different email to avoid constraint
	user2, err := NewUser("", "different_email@example.com", "", aud, nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(user2))

	// But create identity with same email as user1 to simulate the conflict scenario
	identity2, err := NewIdentity(user2, "google", map[string]interface{}{
		"sub":   "google_user_id",
		"email": email, // This creates the conflict at identity level
	})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(identity2))

	// Now try SAML SSO with the same email
	samlProviderType := "sso:12345678-1234-5678-9abc-123456789012"
	samlSubject := "saml_user_id_from_entra_id"

	samlEmails := []provider.Email{
		{
			Email:    email,
			Verified: true,
			Primary:  true,
		},
	}

	// With our fix, SSO now checks for similar users. 
	// Even though there are multiple identities with the same email,
	// there's only one user (user1) with that email, so it should link to user1
	decision, err := DetermineAccountLinking(ts.db, ts.config, samlEmails, aud, samlProviderType, samlSubject)
	require.NoError(ts.T(), err)

	// Should link to user1 since that's the only user with the email
	require.Equal(ts.T(), LinkAccount, decision.Decision)
	require.Equal(ts.T(), user1.ID, decision.User.ID)
}