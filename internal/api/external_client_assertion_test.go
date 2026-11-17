package api

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api/provider"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/utilities"
	"golang.org/x/oauth2"
)

func newPrivateKeyJWTModel(issuer string) *models.CustomOAuthProvider {
	return &models.CustomOAuthProvider{
		ID:               uuid.Must(uuid.NewV4()),
		ProviderType:     models.ProviderTypeOIDC,
		Identifier:       "custom:pkjwt",
		ClientID:         "test-client-id",
		Issuer:           &issuer,
		ClientAuthMethod: models.ClientAuthMethodPrivateKeyJWT,
	}
}

func TestCheckClientAssertionAvailable(t *testing.T) {
	enabled := &conf.ClientAssertionConfiguration{
		Enabled:    true,
		SigningKey: func(context.Context) (any, error) { return nil, nil },
	}

	// client_secret providers are never affected
	secretProvider := newPrivateKeyJWTModel("https://issuer.example.com")
	secretProvider.ClientAuthMethod = models.ClientAuthMethodClientSecret
	require.NoError(t, checkClientAssertionAvailable(secretProvider, &conf.ClientAssertionConfiguration{}))

	require.NoError(t, checkClientAssertionAvailable(newPrivateKeyJWTModel("https://issuer.example.com"), enabled))

	err := checkClientAssertionAvailable(newPrivateKeyJWTModel("https://issuer.example.com"), &conf.ClientAssertionConfiguration{})
	require.ErrorContains(t, err, "client assertions are not enabled")

	noKey := &conf.ClientAssertionConfiguration{Enabled: true}
	err = checkClientAssertionAvailable(newPrivateKeyJWTModel("https://issuer.example.com"), noKey)
	require.ErrorContains(t, err, "client assertions are not enabled")

	oauth2Provider := newPrivateKeyJWTModel("https://issuer.example.com")
	oauth2Provider.ProviderType = models.ProviderTypeOAuth2
	oauth2Provider.Issuer = nil
	err = checkClientAssertionAvailable(oauth2Provider, enabled)
	require.ErrorContains(t, err, "requires an OIDC provider")
}

func TestClientAssertionRequestFor(t *testing.T) {
	p := newPrivateKeyJWTModel("https://issuer.example.com")

	req := clientAssertionRequestFor(p)
	assert.Equal(t, p.ID.String(), req.ProviderID)
	assert.Equal(t, "test-client-id", req.ClientID)
	assert.Equal(t, "https://issuer.example.com", req.Audience, "defaults to the issuer")

	audience := "https://issuer.example.com/token"
	p.ClientAssertionAudience = &audience
	assert.Equal(t, audience, clientAssertionRequestFor(p).Audience, "the override wins")
}

// TestLoadCustomProviderFailsClosedForPrivateKeyJWT checks that a
// private_key_jwt provider can't be loaded while client assertions are off,
// so neither the authorize redirect nor the token exchange can happen.
func (ts *CustomOAuthAdminTestSuite) TestLoadCustomProviderFailsClosedForPrivateKeyJWT() {
	provider := ts.createOIDCProviderInDB("pkjwt-fail-closed", "https://pkjwt-fail-closed.example.com")
	provider.ClientAuthMethod = models.ClientAuthMethodPrivateKeyJWT
	provider.ClientSecret = ""
	require.NoError(ts.T(), models.UpdateCustomOAuthProvider(ts.API.db, provider))

	_, _, err := ts.API.loadCustomProvider(context.Background(), ts.API.db, provider.Identifier, "")
	require.ErrorContains(ts.T(), err, "client assertions are not enabled")
}

// TestLoadCustomProviderUsesClientAssertion checks that a private_key_jwt
// provider loaded with client assertions enabled authenticates its token
// exchange with a signed assertion instead of a client secret.
func (ts *CustomOAuthAdminTestSuite) TestLoadCustomProviderUsesClientAssertion() {
	var tokenForm url.Values
	var server *httptest.Server
	// TLS, because custom OIDC issuers must be https
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_, _ = w.Write([]byte(`{"issuer":"` + server.URL + `","authorization_endpoint":"` + server.URL +
				`/authorize","token_endpoint":"` + server.URL + `/token","jwks_uri":"` + server.URL + `/jwks"}`))
		case "/token":
			require.NoError(ts.T(), r.ParseForm())
			tokenForm = r.PostForm
			_, _ = w.Write([]byte(`{"access_token":"test-access-token","token_type":"Bearer","expires_in":3600}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// the production fetcher rejects loopback addresses
	restore := utilities.SetOIDCDiscoveryHTTPFetcherForTest(func(ctx context.Context, discoveryURL string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
		if err != nil {
			return nil, err
		}
		return server.Client().Do(req)
	})
	defer restore()
	// the token exchange trusts the test server's certificate
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, server.Client())

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(ts.T(), err)
	signingJwk, err := jwk.FromRaw(key)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), signingJwk.Set(jwk.KeyIDKey, "assertion-key"))
	require.NoError(ts.T(), signingJwk.Set(jwk.AlgorithmKey, "RS256"))
	ts.Config.Experimental.ClientAssertion = conf.ClientAssertionConfiguration{
		Enabled:    true,
		SigningJwk: signingJwk,
		SigningKey: func(context.Context) (any, error) { return key, nil },
	}

	model := ts.createOIDCProviderInDB("pkjwt-load", server.URL)
	model.ClientAuthMethod = models.ClientAuthMethodPrivateKeyJWT
	model.ClientSecret = ""
	require.NoError(ts.T(), models.UpdateCustomOAuthProvider(ts.API.db, model))

	p, _, err := ts.API.loadCustomProvider(ctx, ts.API.db, model.Identifier, "")
	require.NoError(ts.T(), err)
	oauthProvider, ok := p.(provider.OAuthProvider)
	require.True(ts.T(), ok)
	_, err = oauthProvider.GetOAuthToken(ctx, "test-code")
	require.NoError(ts.T(), err)

	require.NotNil(ts.T(), tokenForm, "the token endpoint was called")
	assert.NotContains(ts.T(), tokenForm, "client_secret")
	assert.Equal(ts.T(), "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", tokenForm.Get("client_assertion_type"))
	_, err = jwt.Parse(tokenForm.Get("client_assertion"), func(*jwt.Token) (any, error) { return &key.PublicKey, nil },
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithAudience(server.URL),
		jwt.WithIssuer("test-client-id"),
		jwt.WithSubject("test-client-id"),
	)
	require.NoError(ts.T(), err)
}
