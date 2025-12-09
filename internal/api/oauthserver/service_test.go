package oauthserver

import (
	"context"
	"testing"

	"github.com/gobwas/glob"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/hooks/v0hooks"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/storage/test"
	"github.com/supabase/auth/internal/tokens"
)

const serviceTestConfig = "../../../hack/test.env"

// OAuthServiceTestSuite runs tests for OAuth service layer functionality
type OAuthServiceTestSuite struct {
	suite.Suite
	Server *Server
	Config *conf.GlobalConfiguration
	DB     *storage.Connection
}

func TestOAuthService(t *testing.T) {
	globalConfig, err := conf.LoadGlobal(serviceTestConfig)
	require.NoError(t, err)

	conn, err := test.SetupDBConnection(globalConfig)
	require.NoError(t, err)

	// Enable OAuth server and dynamic client registration for tests
	globalConfig.OAuthServer.Enabled = true
	globalConfig.OAuthServer.AllowDynamicRegistration = true

	// Create a mock hooks manager for token service
	hooksMgr := &v0hooks.Manager{} // minimal mock for testing
	tokenService := tokens.NewService(globalConfig, hooksMgr)

	server := NewServer(globalConfig, conn, tokenService)

	ts := &OAuthServiceTestSuite{
		Server: server,
		Config: globalConfig,
		DB:     conn,
	}
	defer ts.DB.Close()

	suite.Run(t, ts)
}

func (ts *OAuthServiceTestSuite) SetupTest() {
	if ts.DB != nil {
		models.TruncateAll(ts.DB)
	}
	// Enable OAuth server and dynamic client registration for tests
	ts.Config.OAuthServer.Enabled = true
	ts.Config.OAuthServer.AllowDynamicRegistration = true
	
	// Add test URIs to allow list for testing
	ts.Config.URIAllowList = append(ts.Config.URIAllowList, "https://example.com/**", "https://app.example.com/**", "http://localhost:3000/**", "http://127.0.0.1:8080/**")
	// Rebuild the allow list map
	ts.Config.URIAllowListMap = make(map[string]glob.Glob)
	for _, uri := range ts.Config.URIAllowList {
		g := glob.MustCompile(uri, '.', '/')
		ts.Config.URIAllowListMap[uri] = g
	}
}

// Helper function to create test OAuth client
func (ts *OAuthServiceTestSuite) createTestOAuthClient() (*models.OAuthServerClient, string) {
	params := &OAuthServerClientRegisterParams{
		ClientName:       "Test Client",
		RedirectURIs:     []string{"https://example.com/callback", "http://localhost:3000/callback"},
		RegistrationType: "dynamic",
	}

	ctx := context.Background()
	client, secret, err := ts.Server.registerOAuthServerClient(ctx, params)
	require.NoError(ts.T(), err)
	require.NotNil(ts.T(), client)
	require.NotEmpty(ts.T(), secret)

	return client, secret
}

// Test the OAuth client service functions directly
func (ts *OAuthServiceTestSuite) TestOAuthServerClientServiceMethods() {

	// Test registerOAuthServerClient
	params := &OAuthServerClientRegisterParams{
		ClientName:       "Test Client",
		RedirectURIs:     []string{"https://example.com/callback"},
		RegistrationType: "dynamic",
	}

	ctx := context.Background()
	client, secret, err := ts.Server.registerOAuthServerClient(ctx, params)

	require.NoError(ts.T(), err)
	require.NotNil(ts.T(), client)
	require.NotEmpty(ts.T(), secret)
	assert.Equal(ts.T(), "Test Client", *client.ClientName)
	assert.Equal(ts.T(), "dynamic", client.RegistrationType)

	// Test getOAuthServerClient
	retrievedClient, err := ts.Server.getOAuthServerClient(ctx, client.ID)
	require.NoError(ts.T(), err)
	assert.Equal(ts.T(), client.ID, retrievedClient.ID)

}

func (ts *OAuthServiceTestSuite) TestHashClientSecret() {
	secret := "test-secret-123"

	hash, err := hashClientSecret(secret)
	require.NoError(ts.T(), err)
	assert.NotEmpty(ts.T(), hash)
	assert.NotEqual(ts.T(), secret, hash) // Should be hashed, not plaintext

	// Test validation
	isValid := ValidateClientSecret(secret, hash)
	assert.True(ts.T(), isValid)

	isInvalid := ValidateClientSecret("wrong-secret", hash)
	assert.False(ts.T(), isInvalid)
}

func (ts *OAuthServiceTestSuite) TestClientAuthentication() {

	client, secret := ts.createTestOAuthClient()

	// Test valid client credentials
	valid := ValidateClientSecret(secret, client.ClientSecretHash)
	assert.True(ts.T(), valid)

	// Test invalid client credentials
	invalid := ValidateClientSecret("wrong-secret", client.ClientSecretHash)
	assert.False(ts.T(), invalid)
}

func (ts *OAuthServiceTestSuite) TestDeleteOAuthServerClient() {
	// Create a test client first
	client, _ := ts.createTestOAuthClient()

	// Delete the client
	ctx := context.Background()
	err := ts.Server.deleteOAuthServerClient(ctx, client.ID)
	require.NoError(ts.T(), err)

	// Verify client was soft-deleted
	deletedClient, err := ts.Server.getOAuthServerClient(ctx, client.ID)
	assert.Error(ts.T(), err) // it was soft-deleted
	assert.Nil(ts.T(), deletedClient)
}

func (ts *OAuthServiceTestSuite) TestValidationEdgeCases() {
	// Test empty redirect URIs
	params := &OAuthServerClientRegisterParams{
		ClientName:       "Test Client",
		RedirectURIs:     []string{}, // Empty array
		RegistrationType: "dynamic",
	}

	ctx := context.Background()
	_, _, err := ts.Server.registerOAuthServerClient(ctx, params)
	assert.Error(ts.T(), err)
	assert.Contains(ts.T(), err.Error(), "redirect_uris is required")

	// Test invalid redirect URI
	params = &OAuthServerClientRegisterParams{
		ClientName:       "Test Client",
		RedirectURIs:     []string{"invalid-uri"}, // Invalid URI
		RegistrationType: "dynamic",
	}

	_, _, err = ts.Server.registerOAuthServerClient(ctx, params)
	assert.Error(ts.T(), err)
	assert.Contains(ts.T(), err.Error(), "invalid redirect_uri")

	// Test too many redirect URIs
	params = &OAuthServerClientRegisterParams{
		ClientName:       "Test Client",
		RedirectURIs:     make([]string, 11), // Too many URIs
		RegistrationType: "dynamic",
	}

	// Fill with valid URIs
	for i := 0; i < 11; i++ {
		params.RedirectURIs[i] = "https://example.com/callback" + string(rune('0'+i))
	}

	_, _, err = ts.Server.registerOAuthServerClient(ctx, params)
	assert.Error(ts.T(), err)
	assert.Contains(ts.T(), err.Error(), "redirect_uris cannot exceed 10 items")

	// Test invalid grant type
	params = &OAuthServerClientRegisterParams{
		ClientName:       "Test Client",
		RedirectURIs:     []string{"https://example.com/callback"},
		GrantTypes:       []string{"invalid_grant_type"},
		RegistrationType: "dynamic",
	}

	_, _, err = ts.Server.registerOAuthServerClient(ctx, params)
	assert.Error(ts.T(), err)
	assert.Contains(ts.T(), err.Error(), "grant_types must only contain 'authorization_code' and/or 'refresh_token'")

	// Test client name too long
	params = &OAuthServerClientRegisterParams{
		ClientName:       string(make([]byte, 1025)), // Too long
		RedirectURIs:     []string{"https://example.com/callback"},
		RegistrationType: "dynamic",
	}

	_, _, err = ts.Server.registerOAuthServerClient(ctx, params)
	assert.Error(ts.T(), err)
	assert.Contains(ts.T(), err.Error(), "client_name cannot exceed 1024 characters")

	// Test invalid client URI
	params = &OAuthServerClientRegisterParams{
		ClientName:       "Test Client",
		RedirectURIs:     []string{"https://example.com/callback"},
		ClientURI:        "not-a-valid-url",
		RegistrationType: "dynamic",
	}

	_, _, err = ts.Server.registerOAuthServerClient(ctx, params)
	assert.Error(ts.T(), err)
	assert.Contains(ts.T(), err.Error(), "client_uri must be a valid URL")

	// Test invalid logo URI
	params = &OAuthServerClientRegisterParams{
		ClientName:       "Test Client",
		RedirectURIs:     []string{"https://example.com/callback"},
		LogoURI:          "not-a-valid-url",
		RegistrationType: "dynamic",
	}

	_, _, err = ts.Server.registerOAuthServerClient(ctx, params)
	assert.Error(ts.T(), err)
	assert.Contains(ts.T(), err.Error(), "logo_uri must be a valid URL")

	// Test invalid registration type
	params = &OAuthServerClientRegisterParams{
		ClientName:       "Test Client",
		RedirectURIs:     []string{"https://example.com/callback"},
		RegistrationType: "invalid",
	}

	_, _, err = ts.Server.registerOAuthServerClient(ctx, params)
	assert.Error(ts.T(), err)
	assert.Contains(ts.T(), err.Error(), "registration_type must be 'dynamic' or 'manual'")
}

func (ts *OAuthServiceTestSuite) TestRedirectURIValidation() {
	testCases := []struct {
		name        string
		uri         string
		shouldError bool
		errorMsg    string
	}{
		{
			name:        "Valid HTTPS URI",
			uri:         "https://example.com/callback",
			shouldError: false,
		},
		{
			name:        "Valid localhost HTTP URI",
			uri:         "http://localhost:3000/callback",
			shouldError: false,
		},
		{
			name:        "Valid 127.0.0.1 HTTP URI",
			uri:         "http://127.0.0.1:8080/callback",
			shouldError: false,
		},
		{
			name:        "Invalid empty URI",
			uri:         "",
			shouldError: true,
			errorMsg:    "redirect URI cannot be empty",
		},
		{
			name:        "Invalid URI with fragment",
			uri:         "https://example.com/callback#fragment",
			shouldError: true,
			errorMsg:    "fragment not allowed in redirect URI",
		},
		{
			name:        "Invalid URI format",
			uri:         "not-a-uri",
			shouldError: true,
			errorMsg:    "must have scheme",
		},
		{
			name:        "URI not in allow list",
			uri:         "ftp://example.com/callback",
			shouldError: true,
			errorMsg:    "not allowed by configuration",
		},
		{
			name:        "Dangerous javascript scheme blocked",
			uri:         "javascript:alert('xss')",
			shouldError: true,
			errorMsg:    "not allowed for security reasons",
		},
		{
			name:        "Dangerous data scheme blocked",
			uri:         "data:text/html,<script>alert('xss')</script>",
			shouldError: true,
			errorMsg:    "not allowed for security reasons",
		},
		{
			name:        "Dangerous file scheme blocked",
			uri:         "file:///etc/passwd",
			shouldError: true,
			errorMsg:    "not allowed for security reasons",
		},
	}

	for _, tc := range testCases {
		ts.T().Run(tc.name, func(t *testing.T) {
			err := ts.Server.validateRedirectURI(tc.uri)
			if tc.shouldError {
				assert.Error(t, err)
				if tc.errorMsg != "" {
					assert.Contains(t, err.Error(), tc.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func (ts *OAuthServiceTestSuite) TestGrantTypeDefaults() {

	// Test that default grant types are set when none provided
	params := &OAuthServerClientRegisterParams{
		ClientName:       "Test Client",
		RedirectURIs:     []string{"https://example.com/callback"},
		RegistrationType: "dynamic",
		// GrantTypes not specified
	}

	ctx := context.Background()
	client, _, err := ts.Server.registerOAuthServerClient(ctx, params)
	require.NoError(ts.T(), err)

	// Should have default grant types
	grantTypes := client.GetGrantTypes()
	assert.Contains(ts.T(), grantTypes, "authorization_code")
	assert.Contains(ts.T(), grantTypes, "refresh_token")
	assert.Len(ts.T(), grantTypes, 2)
}

func (ts *OAuthServiceTestSuite) TestCustomURISchemes() {
	// Test custom URI schemes when they're in the allow list
	// This tests the fix for issue #2285

	// Save original allow list
	originalAllowList := ts.Config.URIAllowList
	originalAllowListMap := ts.Config.URIAllowListMap
	defer func() {
		ts.Config.URIAllowList = originalAllowList
		ts.Config.URIAllowListMap = originalAllowListMap
	}()

	// Configure allow list with custom schemes (keep existing + add custom)
	ts.Config.URIAllowList = append([]string{}, originalAllowList...)
	ts.Config.URIAllowList = append(ts.Config.URIAllowList, "cursor://**", "com.example.app://**", "exp://**")
	// Rebuild the allow list map
	ts.Config.URIAllowListMap = make(map[string]glob.Glob)
	for _, uri := range ts.Config.URIAllowList {
		g := glob.MustCompile(uri, '.', '/')
		ts.Config.URIAllowListMap[uri] = g
	}

	ctx := context.Background()

	// Test 1: cursor:// scheme (for Cursor IDE)
	params := &OAuthServerClientRegisterParams{
		ClientName:       "Cursor IDE",
		RedirectURIs:     []string{"cursor://anysphere.cursor-mcp/callback"},
		RegistrationType: "dynamic",
	}

	client, secret, err := ts.Server.registerOAuthServerClient(ctx, params)
	require.NoError(ts.T(), err, "Should allow cursor:// scheme when in allow list")
	require.NotNil(ts.T(), client)
	require.NotEmpty(ts.T(), secret)
	assert.Equal(ts.T(), "Cursor IDE", *client.ClientName)
	assert.Equal(ts.T(), []string{"cursor://anysphere.cursor-mcp/callback"}, client.GetRedirectURIs())

	// Test 2: Mobile app scheme (com.example.app://)
	params = &OAuthServerClientRegisterParams{
		ClientName:       "Mobile App",
		RedirectURIs:     []string{"com.example.app://sign-in/v2"},
		RegistrationType: "dynamic",
	}

	client, secret, err = ts.Server.registerOAuthServerClient(ctx, params)
	require.NoError(ts.T(), err, "Should allow com.example.app:// scheme when in allow list")
	require.NotNil(ts.T(), client)
	require.NotEmpty(ts.T(), secret)
	assert.Equal(ts.T(), "Mobile App", *client.ClientName)

	// Test 3: Expo scheme (exp://)
	params = &OAuthServerClientRegisterParams{
		ClientName:       "Expo App",
		RedirectURIs:     []string{"exp://192.168.1.1:19000/--/auth/callback"},
		RegistrationType: "dynamic",
	}

	client, secret, err = ts.Server.registerOAuthServerClient(ctx, params)
	require.NoError(ts.T(), err, "Should allow exp:// scheme when in allow list")
	require.NotNil(ts.T(), client)
	require.NotEmpty(ts.T(), secret)

	// Test 4: Unauthorized custom scheme should fail
	params = &OAuthServerClientRegisterParams{
		ClientName:       "Malicious App",
		RedirectURIs:     []string{"malicious://attack"},
		RegistrationType: "dynamic",
	}

	_, _, err = ts.Server.registerOAuthServerClient(ctx, params)
	assert.Error(ts.T(), err, "Should reject custom scheme not in allow list")
	assert.Contains(ts.T(), err.Error(), "redirect URI not allowed by configuration")

	// Test 5: Mix of custom and standard schemes
	params = &OAuthServerClientRegisterParams{
		ClientName:       "Multi-Platform App",
		RedirectURIs:     []string{"https://example.com/callback", "cursor://app/callback"},
		RegistrationType: "dynamic",
	}

	client, secret, err = ts.Server.registerOAuthServerClient(ctx, params)
	require.NoError(ts.T(), err, "Should allow mix of standard and custom schemes")
	require.NotNil(ts.T(), client)
	require.NotEmpty(ts.T(), secret)
	assert.Len(ts.T(), client.GetRedirectURIs(), 2)
}
