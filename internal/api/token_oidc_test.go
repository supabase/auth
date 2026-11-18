package api

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gobuffalo/pop/v6/slices"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/api/provider"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/mailer/mockclient"
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

// supabase/auth#2925: an email-optional custom OIDC provider (e.g. LINE with
// only the openid scope) issues ID tokens without an email. Linking such an
// identity to a user who has no email must not ask for an email confirmation.
func TestIdTokenGrantLinksEmailOptionalIdentityWithoutEmail(t *testing.T) {
	mockMailer := &mockclient.MockMailer{}
	api, config, err := setupAPIForTest(WithMailer(mockMailer))
	require.NoError(t, err)
	t.Cleanup(func() { api.db.Close() })
	require.NoError(t, models.TruncateAll(api.db))

	customOAuthEnabled := config.CustomOAuth.Enabled
	config.CustomOAuth.Enabled = true
	t.Cleanup(func() { config.CustomOAuth.Enabled = customOAuthEnabled })

	// custom_oauth_providers requires an https issuer, hence a TLS server.
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                 server.URL,
			"authorization_endpoint": server.URL + "/authorize",
			"token_endpoint":         server.URL + "/token",
			"jwks_uri":               server.URL + "/jwks",
		})
	}))
	t.Cleanup(server.Close)

	issuer := server.URL
	customProvider := &models.CustomOAuthProvider{
		ProviderType:        models.ProviderTypeOIDC,
		Identifier:          "custom:line",
		Name:                "LINE",
		ClientID:            "line-client-id",
		ClientSecret:        "line-client-secret",
		Enabled:             true,
		EmailOptional:       true,
		Issuer:              &issuer,
		AttributeMapping:    slices.Map{},
		AuthorizationParams: slices.Map{},
	}
	require.NoError(t, models.CreateCustomOAuthProvider(api.db, customProvider))
	t.Cleanup(func() { _ = models.DeleteCustomOAuthProvider(api.db, customProvider.ID) })

	// Discover the provider through the test server's own client and keep it
	// in the cache, so the grant does not need the default HTTP client to
	// trust the test certificate.
	t.Cleanup(utilities.SetOIDCDiscoveryHTTPFetcherForTest(
		func(ctx context.Context, discoveryURL string) (*http.Response, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
			if err != nil {
				return nil, err
			}
			return server.Client().Do(req)
		},
	))
	_, err = api.oidcCache.GetProviderFromURL(context.Background(), issuer, customProvider.GetDiscoveryURL())
	require.NoError(t, err)

	// Trust the in-test signing key for ID tokens from this provider.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	provider.OverrideVerifiers[server.URL+"/authorize"] = func(ctx context.Context, config *oidc.Config) *oidc.IDTokenVerifier {
		return oidc.NewVerifier(issuer, &oidc.StaticKeySet{
			PublicKeys: []crypto.PublicKey{&key.PublicKey},
		}, config)
	}
	t.Cleanup(func() { delete(provider.OverrideVerifiers, server.URL+"/authorize") })

	// An ID token without an email claim.
	now := time.Now()
	idToken, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": issuer,
		"aud": customProvider.ClientID,
		"sub": "line-user-1",
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}).SignedString(key)
	require.NoError(t, err)

	// A signed-in anonymous user: no email, no phone.
	user, err := models.NewUser("", "", "", config.JWT.Aud, nil)
	require.NoError(t, err)
	user.IsAnonymous = true
	require.NoError(t, api.db.Create(user))
	session, err := models.NewSession(user.ID, nil)
	require.NoError(t, err)
	require.NoError(t, api.db.Create(session))
	accessToken, _, err := api.generateAccessToken(
		httptest.NewRequest(http.MethodPost, "/token?grant_type=password", nil),
		api.db, user, &session.ID, models.PasswordGrant)
	require.NoError(t, err)

	var body bytes.Buffer
	require.NoError(t, json.NewEncoder(&body).Encode(map[string]interface{}{
		"provider":      customProvider.Identifier,
		"id_token":      idToken,
		"link_identity": true,
	}))
	req := httptest.NewRequest(http.MethodPost, "/token?grant_type=id_token", &body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	w := httptest.NewRecorder()
	api.handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Empty(t, mockMailer.ConfirmationMailCalls, "no confirmation email can be sent without an email address")

	identity, err := models.FindIdentityByIdAndProvider(api.db, "line-user-1", customProvider.Identifier)
	require.NoError(t, err)
	require.Equal(t, user.ID, identity.UserID)

	linkedUser, err := models.FindUserByID(api.db, user.ID)
	require.NoError(t, err)
	require.False(t, linkedUser.IsAnonymous, "linking an identity converts the anonymous user")
	require.Empty(t, linkedUser.GetEmail())
	require.Nil(t, linkedUser.EmailConfirmedAt, "there is no email to confirm")
}
