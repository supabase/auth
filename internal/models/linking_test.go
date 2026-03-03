package models

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/api/provider"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/storage/test"
)

type AccountLinkingTestSuite struct {
	suite.Suite

	config *conf.GlobalConfiguration
	db     *storage.Connection
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
		config: globalConfig,
		db:     conn,
	}
	defer ts.db.Close()

	suite.Run(t, ts)
}

func (ts *AccountLinkingTestSuite) TestCreateAccountDecisionNoAccounts() {
	// when there are no accounts in the system -- conventional provider
	testEmail := provider.Email{
		Email:    "test@example.com",
		Verified: true,
		Primary:  true,
	}
	decision, err := DetermineAccountLinking(ts.db, ts.config, []provider.Email{testEmail}, ts.config.JWT.Aud, "provider", "abcdefgh")
	require.NoError(ts.T(), err)

	require.Equal(ts.T(), decision.Decision, CreateAccount)

	// when there are no accounts in the system -- SSO provider
	decision, err = DetermineAccountLinking(ts.db, ts.config, []provider.Email{testEmail}, ts.config.JWT.Aud, "sso:f06f9e3d-ff92-4c47-a179-7acf1fda6387", "abcdefgh")
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

	ssoProvider := "sso:f06f9e3d-ff92-4c47-a179-7acf1fda6387"
	identityB, err := NewIdentity(userB, ssoProvider, map[string]interface{}{
		"sub":   userB.ID.String(),
		"email": "test@samltest.id",
	})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(identityB))

	// when the email doesn't exist in the system -- conventional provider
	decision, err := DetermineAccountLinking(ts.db, ts.config, []provider.Email{
		{
			Email:    "other@example.com",
			Verified: true,
			Primary:  true,
		},
	}, ts.config.JWT.Aud, "provider", "abcdefgh")
	require.NoError(ts.T(), err)

	require.Equal(ts.T(), decision.Decision, CreateAccount)
	require.Equal(ts.T(), decision.LinkingDomain, "default")

	// when looking for an email that doesn't exist in the SSO linking domain
	decision, err = DetermineAccountLinking(ts.db, ts.config, []provider.Email{
		{
			Email:    "other@samltest.id",
			Verified: true,
			Primary:  true,
		},
	}, ts.config.JWT.Aud, ssoProvider, "abcdefgh")
	require.NoError(ts.T(), err)

	require.Equal(ts.T(), decision.Decision, CreateAccount)
	require.Equal(ts.T(), decision.LinkingDomain, ssoProvider)
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

	decision, err := DetermineAccountLinking(ts.db, ts.config, []provider.Email{
		{
			Email:    "test@example.com",
			Verified: true,
			Primary:  true,
		},
	}, ts.config.JWT.Aud, "provider", userA.ID.String())
	require.NoError(ts.T(), err)

	require.Equal(ts.T(), decision.Decision, AccountExists)
	require.Equal(ts.T(), decision.User.ID, userA.ID)
}

func (ts *AccountLinkingTestSuite) TestLinkingScenarios() {
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

	cases := []struct {
		desc     string
		email    provider.Email
		sub      string
		provider string
		decision AccountLinkingResult
	}{
		{
			// link decision because the below described identity is in the default linking domain but uses "other-provider" instead of "provder"
			desc: "same email address",
			email: provider.Email{
				Email:    "test@example.com",
				Verified: true,
				Primary:  true,
			},
			sub:      userA.ID.String(),
			provider: "other-provider",
			decision: AccountLinkingResult{
				Decision:      LinkAccount,
				User:          userA,
				LinkingDomain: "default",
				CandidateEmail: provider.Email{
					Email:    "test@example.com",
					Verified: true,
					Primary:  true,
				},
			},
		},
		{
			desc: "same email address in uppercase",
			email: provider.Email{
				Email:    "TEST@example.com",
				Verified: true,
				Primary:  true,
			},
			sub:      userA.ID.String(),
			provider: "other-provider",
			decision: AccountLinkingResult{
				Decision:      LinkAccount,
				User:          userA,
				LinkingDomain: "default",
				CandidateEmail: provider.Email{
					// expected email should be case insensitive
					Email:    "test@example.com",
					Verified: true,
					Primary:  true,
				},
			},
		},
		{
			desc: "no link decision because the SSO linking domain is scoped to the provider unique ID",
			email: provider.Email{
				Email:    "test@samltest.id",
				Verified: true,
				Primary:  true,
			},
			sub:      userB.ID.String(),
			provider: "sso:f06f9e3d-ff92-4c47-a179-7acf1fda6387",
			// decision: AccountExists,
			decision: AccountLinkingResult{
				Decision:      AccountExists,
				User:          userB,
				LinkingDomain: "sso:f06f9e3d-ff92-4c47-a179-7acf1fda6387",
				CandidateEmail: provider.Email{
					Email:    "test@samltest.id",
					Verified: true,
					Primary:  true,
				},
			},
		},
		{
			desc: "create account with empty email because email is unverified and user exists",
			email: provider.Email{
				Email:    "test@example.com",
				Verified: false,
				Primary:  true,
			},
			sub:      userA.ID.String(),
			provider: "other-provider",
			decision: AccountLinkingResult{
				Decision:      CreateAccount,
				LinkingDomain: "default",
				CandidateEmail: provider.Email{
					Email:    "",
					Verified: false,
					Primary:  true,
				},
			},
		},
		{
			desc: "create account because email is unverified and user doesn't exist",
			email: provider.Email{
				Email:    "other@example.com",
				Verified: false,
				Primary:  true,
			},
			sub:      "000000000",
			provider: "other-provider",
			decision: AccountLinkingResult{
				Decision:      CreateAccount,
				LinkingDomain: "default",
				CandidateEmail: provider.Email{
					Email:    "other@example.com",
					Verified: false,
					Primary:  true,
				},
			},
		},
	}

	for _, c := range cases {
		ts.Run(c.desc, func() {
			decision, err := DetermineAccountLinking(ts.db, ts.config, []provider.Email{c.email}, ts.config.JWT.Aud, c.provider, c.sub)
			require.NoError(ts.T(), err)
			require.Equal(ts.T(), c.decision.Decision, decision.Decision)
			require.Equal(ts.T(), c.decision.LinkingDomain, decision.LinkingDomain)
			require.Equal(ts.T(), c.decision.CandidateEmail.Email, decision.CandidateEmail.Email)
			require.Equal(ts.T(), c.decision.CandidateEmail.Verified, decision.CandidateEmail.Verified)
			require.Equal(ts.T(), c.decision.CandidateEmail.Primary, decision.CandidateEmail.Primary)
		})
	}

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
	decision, err := DetermineAccountLinking(ts.db, ts.config, []provider.Email{
		{
			Email:    "test@example.com",
			Verified: true,
			Primary:  true,
		},
	}, ts.config.JWT.Aud, "provider", "abcdefgh")
	require.NoError(ts.T(), err)

	require.Equal(ts.T(), decision.Decision, MultipleAccounts)
}

func (ts *AccountLinkingTestSuite) TestGetAccountLinkingDomainSSO() {
	ssoProvider := "sso:f06f9e3d-ff92-4c47-a179-7acf1fda6387"

	// When DangerousSSOAutoLinking is disabled, SSO providers get their own isolated domain
	domain := GetAccountLinkingDomain(ssoProvider, nil, false)
	require.Equal(ts.T(), ssoProvider, domain, "SSO should get its own domain when DangerousSSOAutoLinking is disabled")

	// When DangerousSSOAutoLinking is enabled, SSO providers join the default domain
	domain = GetAccountLinkingDomain(ssoProvider, nil, true)
	require.Equal(ts.T(), "default", domain, "SSO should join default domain when DangerousSSOAutoLinking is enabled")

	// Regular OAuth providers always get default domain regardless of the flag
	domain = GetAccountLinkingDomain("google", nil, false)
	require.Equal(ts.T(), "default", domain)

	domain = GetAccountLinkingDomain("google", nil, true)
	require.Equal(ts.T(), "default", domain)
}

func (ts *AccountLinkingTestSuite) TestSSOAutoLinkingEnabled() {
	// Create an existing user with email/password
	existingUser, err := NewUser("", "test@example.com", "password", ts.config.JWT.Aud, nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(existingUser))
	existingIdentity, err := NewIdentity(existingUser, "email", map[string]interface{}{
		"sub":   existingUser.ID.String(),
		"email": "test@example.com",
	})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(existingIdentity))

	ssoProvider := "sso:f06f9e3d-ff92-4c47-a179-7acf1fda6387"

	// Enable DangerousSSOAutoLinking
	ts.config.Security.DangerousSSOAutoLinking = true
	defer func() {
		ts.config.Security.DangerousSSOAutoLinking = false
	}()

	// Now when SSO user logs in with same email, they should be linked to existing user
	decision, err := DetermineAccountLinking(ts.db, ts.config, []provider.Email{
		{
			Email:    "test@example.com",
			Verified: true,
			Primary:  true,
		},
	}, ts.config.JWT.Aud, ssoProvider, "sso-user-subject-id")
	require.NoError(ts.T(), err)

	require.Equal(ts.T(), LinkAccount, decision.Decision, "SSO should link to existing user when DangerousSSOAutoLinking is enabled")
	require.Equal(ts.T(), "default", decision.LinkingDomain, "SSO should be in default linking domain")
	require.Equal(ts.T(), existingUser.ID, decision.User.ID, "SSO should link to existing user")
}

func (ts *AccountLinkingTestSuite) TestSSOAutoLinkingCreatesNewUserWhenNoMatch() {
	// Enable DangerousSSOAutoLinking
	ts.config.Security.DangerousSSOAutoLinking = true
	defer func() {
		ts.config.Security.DangerousSSOAutoLinking = false
	}()

	ssoProvider := "sso:f06f9e3d-ff92-4c47-a179-7acf1fda6387"

	// When no matching user exists, SSO should still create a new account
	decision, err := DetermineAccountLinking(ts.db, ts.config, []provider.Email{
		{
			Email:    "new-sso-user@example.com",
			Verified: true,
			Primary:  true,
		},
	}, ts.config.JWT.Aud, ssoProvider, "new-sso-subject-id")
	require.NoError(ts.T(), err)

	require.Equal(ts.T(), CreateAccount, decision.Decision, "SSO should create new account when no matching user exists")
	require.Equal(ts.T(), "default", decision.LinkingDomain, "SSO should be in default linking domain even when creating account")
}

func (ts *AccountLinkingTestSuite) TestSSOAutoLinkingDisabledCreatesNewUser() {
	// Create an existing user with email/password
	existingUser, err := NewUser("", "test-disabled@example.com", "password", ts.config.JWT.Aud, nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(existingUser))
	existingIdentity, err := NewIdentity(existingUser, "email", map[string]interface{}{
		"sub":   existingUser.ID.String(),
		"email": "test-disabled@example.com",
	})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(existingIdentity))

	ssoProvider := "sso:f06f9e3d-ff92-4c47-a179-7acf1fda6387"

	// Ensure DangerousSSOAutoLinking is disabled (default)
	ts.config.Security.DangerousSSOAutoLinking = false

	// When SSO user logs in with same email AND DangerousSSOAutoLinking is disabled,
	// they should get a new account (not linked)
	decision, err := DetermineAccountLinking(ts.db, ts.config, []provider.Email{
		{
			Email:    "test-disabled@example.com",
			Verified: true,
			Primary:  true,
		},
	}, ts.config.JWT.Aud, ssoProvider, "sso-user-subject-disabled")
	require.NoError(ts.T(), err)

	require.Equal(ts.T(), CreateAccount, decision.Decision, "SSO should create new account when DangerousSSOAutoLinking is disabled")
	require.Equal(ts.T(), ssoProvider, decision.LinkingDomain, "SSO should be in its own isolated linking domain")
}
