package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gobuffalo/pop/v6/slices"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/utilities"
)

type TokenOIDCTestSuite struct {
	suite.Suite
	API    *API
	Config *conf.GlobalConfiguration
}

func TestTokenOIDC(t *testing.T) {
	api, config, err := setupAPIForTest()
	require.NoError(t, err)

	ts := &TokenOIDCTestSuite{
		API:    api,
		Config: config,
	}
	defer api.db.Close()

	suite.Run(t, ts)
}

func SetupTestOIDCProvider(ts *TokenOIDCTestSuite) *httptest.Server {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"issuer":"` + server.URL + `","authorization_endpoint":"` + server.URL + `/authorize","token_endpoint":"` + server.URL + `/token","jwks_uri":"` + server.URL + `/jwks"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	return server
}

func (ts *TokenOIDCTestSuite) TestGetProvider() {
	server := SetupTestOIDCProvider(ts)
	defer server.Close()

	params := &IdTokenGrantParams{
		IdToken:     "test-id-token",
		AccessToken: "test-access-token",
		Nonce:       "test-nonce",
		Provider:    server.URL,
		ClientID:    "test-client-id",
		Issuer:      server.URL,
	}

	ts.Config.External.AllowedIdTokenIssuers = []string{server.URL}

	req := httptest.NewRequest(http.MethodPost, "http://localhost", nil)
	oidcProvider, skipNonceCheck, providerType, acceptableClientIds, emailOptional, err := params.getProvider(context.Background(), ts.API.db, ts.Config, req, ts.API.oidcCache)
	require.NoError(ts.T(), err)
	require.NotNil(ts.T(), oidcProvider)
	require.False(ts.T(), skipNonceCheck)
	require.False(ts.T(), emailOptional)
	require.Equal(ts.T(), params.Provider, providerType)
	require.NotEmpty(ts.T(), acceptableClientIds)
}

// setupTLSOIDCDiscoveryServer starts a TLS test server that serves an OIDC
// discovery document only at discoveryPath and answers 404 everywhere else.
// custom_oauth_providers requires https issuer and discovery URLs, hence TLS.
// It also routes the SSRF-protected discovery fetcher to the server's own
// client, which trusts the test certificate.
func (ts *TokenOIDCTestSuite) setupTLSOIDCDiscoveryServer(discoveryPath string) *httptest.Server {
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != discoveryPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"issuer":"` + server.URL + `","authorization_endpoint":"` + server.URL + `/authorize","token_endpoint":"` + server.URL + `/token","jwks_uri":"` + server.URL + `/jwks"}`))
	}))
	ts.T().Cleanup(server.Close)

	ts.T().Cleanup(utilities.SetOIDCDiscoveryHTTPFetcherForTest(
		func(ctx context.Context, discoveryURL string) (*http.Response, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
			if err != nil {
				return nil, err
			}
			return server.Client().Do(req)
		},
	))
	return server
}

func (ts *TokenOIDCTestSuite) createCustomOIDCProvider(identifier, issuer string, discoveryURL *string) {
	provider := &models.CustomOAuthProvider{
		ProviderType:        models.ProviderTypeOIDC,
		Identifier:          identifier,
		Name:                "Test OIDC provider",
		ClientID:            "test-client-id",
		ClientSecret:        "test-client-secret",
		Enabled:             true,
		Issuer:              &issuer,
		DiscoveryURL:        discoveryURL,
		AttributeMapping:    slices.Map{},
		AuthorizationParams: slices.Map{},
	}
	require.NoError(ts.T(), models.CreateCustomOAuthProvider(ts.API.db, provider))
	ts.T().Cleanup(func() {
		require.NoError(ts.T(), models.DeleteCustomOAuthProvider(ts.API.db, provider.ID))
	})
}

// supabase/auth#2899: the browser flow builds a custom OIDC provider from its
// configured discovery_url, but the native id_token grant looked the provider
// up by issuer only, i.e. {issuer}/.well-known/openid-configuration.
func (ts *TokenOIDCTestSuite) TestGetProviderCustomOIDCUsesConfiguredDiscoveryURL() {
	const discoveryPath = "/custom/discovery"
	server := ts.setupTLSOIDCDiscoveryServer(discoveryPath)
	discoveryURL := server.URL + discoveryPath
	ts.createCustomOIDCProvider("custom:discovery-override", server.URL, &discoveryURL)

	prevEnabled := ts.Config.CustomOAuth.Enabled
	ts.Config.CustomOAuth.Enabled = true
	ts.T().Cleanup(func() { ts.Config.CustomOAuth.Enabled = prevEnabled })

	params := &IdTokenGrantParams{
		IdToken:  "test-id-token",
		Nonce:    "test-nonce",
		Provider: "custom:discovery-override",
	}

	// The default HTTP client does not trust the test certificate, so give the
	// OIDC library the TLS server's client for the issuer-based lookup path.
	ctx := oidc.ClientContext(context.Background(), server.Client())
	req := httptest.NewRequest(http.MethodPost, "http://localhost", nil)
	oidcProvider, skipNonceCheck, providerType, acceptableClientIds, _, err := params.getProvider(ctx, ts.API.db, ts.Config, req, ts.API.oidcCache)
	require.NoError(ts.T(), err)
	require.NotNil(ts.T(), oidcProvider)
	require.False(ts.T(), skipNonceCheck)
	require.Equal(ts.T(), "custom:discovery-override", providerType)
	require.Contains(ts.T(), acceptableClientIds, "test-client-id")
	// The endpoints come from the document served at the override URL.
	require.Equal(ts.T(), server.URL+"/authorize", oidcProvider.Endpoint().AuthURL)
}

// A custom OIDC provider without a discovery_url override keeps using the
// standard {issuer}/.well-known/openid-configuration location.
func (ts *TokenOIDCTestSuite) TestGetProviderCustomOIDCWithoutDiscoveryURLUsesIssuer() {
	server := ts.setupTLSOIDCDiscoveryServer("/.well-known/openid-configuration")
	ts.createCustomOIDCProvider("custom:standard-discovery", server.URL, nil)

	prevEnabled := ts.Config.CustomOAuth.Enabled
	ts.Config.CustomOAuth.Enabled = true
	ts.T().Cleanup(func() { ts.Config.CustomOAuth.Enabled = prevEnabled })

	params := &IdTokenGrantParams{
		IdToken:  "test-id-token",
		Nonce:    "test-nonce",
		Provider: "custom:standard-discovery",
	}

	ctx := oidc.ClientContext(context.Background(), server.Client())
	req := httptest.NewRequest(http.MethodPost, "http://localhost", nil)
	oidcProvider, _, providerType, _, _, err := params.getProvider(ctx, ts.API.db, ts.Config, req, ts.API.oidcCache)
	require.NoError(ts.T(), err)
	require.NotNil(ts.T(), oidcProvider)
	require.Equal(ts.T(), "custom:standard-discovery", providerType)
	require.Equal(ts.T(), server.URL+"/authorize", oidcProvider.Endpoint().AuthURL)
}

// createFakeIDToken creates a fake JWT token with a specific issuer claim for testing
// WARNING: This is for testing purposes only and creates an unsigned token
func createFakeIDToken(issuer string, sub string) string {
	header := map[string]interface{}{
		"alg": "RS256",
		"typ": "JWT",
	}

	payload := map[string]interface{}{
		"iss": issuer,
		"sub": sub,
		"aud": "test-client-id",
		"exp": 9999999999,
		"iat": 1234567890,
	}

	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)

	headerEncoded := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Note: signature is fake, but the issuer detection only looks at the payload
	return headerEncoded + "." + payloadEncoded + ".fake-signature"
}

func (ts *TokenOIDCTestSuite) TestGetProviderAppleWithIncorrectIssuer() {
	incorrectIssuer := SetupTestOIDCProvider(ts)
	defer incorrectIssuer.Close()

	ts.Config.External.Apple.Enabled = true
	ts.Config.External.Apple.ClientID = []string{"com.example.app"}

	// Create a token with an invalid issuer
	nonAppleToken := createFakeIDToken(incorrectIssuer.URL, "user123")

	// provider="apple" but with an incorrect issuer in the token
	params := &IdTokenGrantParams{
		IdToken:  nonAppleToken,
		Provider: "apple",
		Issuer:   incorrectIssuer.URL,
	}

	req := httptest.NewRequest(http.MethodPost, "http://localhost", nil)
	_, _, _, _, _, err := params.getProvider(context.Background(), ts.API.db, ts.Config, req, ts.API.oidcCache)

	require.Error(ts.T(), err)
	require.Contains(ts.T(), err.Error(), "not an Apple ID token issuer")
}

// TestGetProviderAzureWithNonAzureTokenIssuer tests that Azure provider only
// accepts tokens from login.microsoftonline.com and sts.windows.net
func (ts *TokenOIDCTestSuite) TestGetProviderAzureWithNonAzureTokenIssuer() {
	ts.Config.External.Azure.Enabled = true
	ts.Config.External.Azure.ClientID = []string{"test-client-id"}

	// Create a token with an incorrect issuer
	nonAzureIssuer := "https://non-azure-issuer.example.com"
	nonAzureToken := createFakeIDToken(nonAzureIssuer, "user123")

	params := &IdTokenGrantParams{
		IdToken:  nonAzureToken,
		Provider: "azure",
		Issuer:   nonAzureIssuer,
	}

	req := httptest.NewRequest(http.MethodPost, "http://localhost", nil)
	_, _, _, _, _, err := params.getProvider(context.Background(), ts.API.db, ts.Config, req, ts.API.oidcCache)

	// This should fail - the token's issuer is not an accepted issuer
	require.Error(ts.T(), err)
	require.Contains(ts.T(), err.Error(), "not an Azure ID token issuer")
}

// TestGetProviderAppleWithInvalidIssuerInToken tests that Apple provider rejects
// tokens when the actual token issuer does not match the expected issuer
func (ts *TokenOIDCTestSuite) TestGetProviderAppleWithNonAppleIssuerInToken() {
	ts.Config.External.Apple.Enabled = true
	ts.Config.External.Apple.ClientID = []string{"com.example.app"}

	// Create a token with an incorrect issuer
	nonAppleIssuer := "https://non-apple-issuer.example.com"
	nonAppleToken := createFakeIDToken(nonAppleIssuer, "user123")

	params := &IdTokenGrantParams{
		IdToken:  nonAppleToken,
		Provider: "apple",
		Issuer:   "https://appleid.apple.com",
	}

	req := httptest.NewRequest(http.MethodPost, "http://localhost", nil)
	_, _, _, _, _, err := params.getProvider(context.Background(), ts.API.db, ts.Config, req, ts.API.oidcCache)

	// This should fail - the token's actual issuer is not appleid.apple.com
	require.Error(ts.T(), err)
	require.Contains(ts.T(), err.Error(), "not an Apple ID token issuer")
}
