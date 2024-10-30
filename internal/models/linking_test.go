package models

import (
	"fmt"
	"testing"

	"github.com/gofrs/uuid"
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
	organization_id := uuid.Must(uuid.FromString("123e4567-e89b-12d3-a456-426655440000"))
	decision, err := DetermineAccountLinking(ts.db, ts.config, []provider.Email{testEmail}, ts.config.JWT.Aud, "provider", "abcdefgh", organization_id, uuid.Nil)
	require.NoError(ts.T(), err)

	require.Equal(ts.T(), decision.Decision, CreateAccount)

	// when there are no accounts in the system -- SSO provider
	decision, err = DetermineAccountLinking(ts.db, ts.config, []provider.Email{testEmail}, ts.config.JWT.Aud, "sso:f06f9e3d-ff92-4c47-a179-7acf1fda6387", "abcdefgh", organization_id, uuid.Nil)
	require.NoError(ts.T(), err)

	require.Equal(ts.T(), decision.Decision, CreateAccount)
}

func (ts *AccountLinkingTestSuite) TestCreateAccountDecisionWithAccounts() {
	id := uuid.Must(uuid.FromString("123e4567-e89b-12d3-a456-426655440000"))
	userA, err := NewUser("", "test@example.com", "", "authenticated", nil, id, uuid.Nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(userA, "project_id", "organization_role"))
	organization_id := uuid.Must(uuid.FromString("123e4567-e89b-12d3-a456-426655440000"))
	identityA, err := NewIdentity(userA, "provider", map[string]interface{}{
		"sub":   userA.ID.String(),
		"email": "test@example.com",
	})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(identityA, "project_id"))

	userB, err := NewUser("", "test@samltest.id", "", "authenticated", nil, id, uuid.Nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(userB, "project_id", "organization_role"))

	ssoProvider := "sso:f06f9e3d-ff92-4c47-a179-7acf1fda6387"
	identityB, err := NewIdentity(userB, ssoProvider, map[string]interface{}{
		"sub":   userB.ID.String(),
		"email": "test@samltest.id",
	})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(identityB, "project_id"))

	// when the email doesn't exist in the system -- conventional provider
	decision, err := DetermineAccountLinking(ts.db, ts.config, []provider.Email{
		{
			Email:    "other@example.com",
			Verified: true,
			Primary:  true,
		},
	}, ts.config.JWT.Aud, "provider", "abcdefgh", organization_id, uuid.Nil)
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
	}, ts.config.JWT.Aud, ssoProvider, "abcdefgh", organization_id, uuid.Nil)
	require.NoError(ts.T(), err)

	require.Equal(ts.T(), decision.Decision, CreateAccount)
	require.Equal(ts.T(), decision.LinkingDomain, ssoProvider)
}

func (ts *AccountLinkingTestSuite) TestAccountExists() {
	organization_id := uuid.Must(uuid.FromString("123e4567-e89b-12d3-a456-426655440000"))
	userA, err := NewUser("", "test@example.com", "", "authenticated", nil, organization_id, uuid.Nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(userA, "project_id", "organization_role"))
	identityA, err := NewIdentity(userA, "provider", map[string]interface{}{
		"sub":   userA.ID.String(),
		"email": "test@example.com",
	})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(identityA, "project_id"))

	decision, err := DetermineAccountLinking(ts.db, ts.config, []provider.Email{
		{
			Email:    "test@example.com",
			Verified: true,
			Primary:  true,
		},
	}, ts.config.JWT.Aud, "provider", userA.ID.String(), organization_id, uuid.Nil)
	require.NoError(ts.T(), err)

	require.Equal(ts.T(), decision.Decision, AccountExists)
	require.Equal(ts.T(), decision.User.ID, userA.ID)
}

func (ts *AccountLinkingTestSuite) TestLinkingScenarios() {
	organization_id := uuid.Must(uuid.FromString("123e4567-e89b-12d3-a456-426655440000"))
	userA, err := NewUser("", "test@example.com", "", "authenticated", nil, organization_id, uuid.Nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(userA, "project_id", "organization_role"))
	identityA, err := NewIdentity(userA, "provider", map[string]interface{}{
		"sub":   userA.ID.String(),
		"email": "test@example.com",
	})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(identityA, "project_id"))

	userB, err := NewUser("", "test@samltest.id", "", "authenticated", nil, organization_id, uuid.Nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(userB, "project_id", "organization_role"))

	identityB, err := NewIdentity(userB, "sso:f06f9e3d-ff92-4c47-a179-7acf1fda6387", map[string]interface{}{
		"sub":   userB.ID.String(),
		"email": "test@samltest.id",
	})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(identityB, "project_id"))

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
			decision, err := DetermineAccountLinking(ts.db, ts.config, []provider.Email{c.email}, ts.config.JWT.Aud, c.provider, c.sub, organization_id, uuid.Nil)
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
	organization_id := uuid.Must(uuid.FromString("123e4567-e89b-12d3-a456-426655440000"))
	userA, err := NewUser("", "test@example.com", "", "authenticated", nil, organization_id, uuid.Nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(userA, "project_id", "organization_role"))
	identityA, err := NewIdentity(userA, "provider", map[string]interface{}{
		"sub":   userA.ID.String(),
		"email": "test@example.com",
	})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(identityA, "project_id"))

	userB, err := NewUser("", "test-b@example.com", "", "authenticated", nil, organization_id, uuid.Nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(userB, "project_id", "organization_role"))
	identityB, err := NewIdentity(userB, "provider", map[string]interface{}{
		"sub":   userB.ID.String(),
		"email": "test@example.com", // intentionally same as userA
	})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(identityB, "project_id"))

	// decision is multiple accounts because there are two distinct
	// identities in the same "default" linking domain with the same email
	// address pointing to two different user accounts
	decision, err := DetermineAccountLinking(ts.db, ts.config, []provider.Email{
		{
			Email:    "test@example.com",
			Verified: true,
			Primary:  true,
		},
	}, ts.config.JWT.Aud, "provider", "abcdefgh", organization_id, uuid.Nil)
	require.NoError(ts.T(), err)

	require.Equal(ts.T(), decision.Decision, MultipleAccounts)
}
