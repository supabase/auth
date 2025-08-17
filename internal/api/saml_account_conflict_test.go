package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/api/provider"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

type SAMLAccountConflictTestSuite struct {
	suite.Suite
	API    *API
	Config *conf.GlobalConfiguration
}

func TestSAMLAccountConflict(t *testing.T) {
	api, config, err := setupAPIForTest()
	require.NoError(t, err)

	ts := &SAMLAccountConflictTestSuite{
		API:    api,
		Config: config,
	}
	defer api.db.Close()

	suite.Run(t, ts)
}

func (ts *SAMLAccountConflictTestSuite) SetupTest() {
	models.TruncateAll(ts.API.db)
}

// TestEmailPasswordSignupThenSAMLSSOLogin demonstrates the exact issue:
// 1. User signs up with email/password
// 2. User tries to login with SAML SSO using same email
// 3. System should link accounts but instead tries to create a new account
func (ts *SAMLAccountConflictTestSuite) TestEmailPasswordSignupThenSAMLSSOLogin() {
	email := "user@example.com"
	password := "password123"

	// Step 1: User signs up with email/password
	var signupBuffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&signupBuffer).Encode(map[string]interface{}{
		"email":    email,
		"password": password,
	}))

	signupReq := httptest.NewRequest(http.MethodPost, "/signup", &signupBuffer)
	signupReq.Header.Set("Content-Type", "application/json")
	signupW := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(signupW, signupReq)
	require.Equal(ts.T(), http.StatusOK, signupW.Code)

	// Verify user was created
	var signupResponse models.User
	require.NoError(ts.T(), json.NewDecoder(signupW.Body).Decode(&signupResponse))
	require.Equal(ts.T(), email, signupResponse.GetEmail())
	require.False(ts.T(), signupResponse.IsSSOUser)

	// Verify user exists in database
	user, err := models.FindUserByEmailAndAudience(ts.API.db, email, ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), email, user.GetEmail())
	require.False(ts.T(), user.IsSSOUser)

	// Check user has email identity
	require.NoError(ts.T(), ts.API.db.Load(user, "Identities"))
	require.Len(ts.T(), user.Identities, 1)
	require.Equal(ts.T(), "email", user.Identities[0].Provider)

	// Step 2: Create a SAML SSO provider for testing
	ssoProvider := &models.SSOProvider{
		SAMLProvider: models.SAMLProvider{
			EntityID:    "https://test-entra-id.com",
			MetadataXML: getMockSAMLMetadata(),
		},
	}
	require.NoError(ts.T(), ts.API.db.Create(ssoProvider))

	// Step 3: Simulate SAML SSO callback with the same email
	// This would normally come from a SAML assertion, but we'll use the createAccountFromExternalIdentity directly
	// to test the core logic without dealing with SAML XML parsing

	// This is the userData that would be extracted from a SAML assertion
	samlUserData := &provider.UserProvidedData{
		Emails: []provider.Email{
			{
				Email:    email,
				Verified: true,
				Primary:  true,
			},
		},
		Metadata: &provider.Claims{
			Subject:       "saml_user_id_from_entra_id",
			Email:         email,
			EmailVerified: true,
		},
	}

	samlProviderType := fmt.Sprintf("sso:%s", ssoProvider.ID.String())

	// Step 4: Test the account linking decision
	// This is where the bug occurs - it should link to existing account but creates new one
	err = ts.API.db.Transaction(func(tx *storage.Connection) error {
		decision, terr := models.DetermineAccountLinking(tx, ts.Config, samlUserData.Emails, ts.Config.JWT.Aud, samlProviderType, samlUserData.Metadata.Subject)
		if terr != nil {
			return terr
		}

		// FIXED: Now correctly links to existing account
		require.Equal(ts.T(), models.LinkAccount, decision.Decision, 
			"Should link to existing email/password account")
		require.Equal(ts.T(), user.ID, decision.User.ID, 
			"Should find the existing user")
		require.Equal(ts.T(), samlProviderType, decision.LinkingDomain)

		return nil
	})
	require.NoError(ts.T(), err)
}

// getMockSAMLMetadata returns a minimal SAML metadata XML for testing
func getMockSAMLMetadata() string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://test-entra-id.com">
  <md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://test-entra-id.com/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>`
}