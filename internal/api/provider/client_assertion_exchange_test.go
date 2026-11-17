package provider

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
	"golang.org/x/oauth2"
)

// fakeTokenEndpoint records every token request it receives.
type fakeTokenEndpoint struct {
	mu       sync.Mutex
	requests []recordedTokenRequest
	// reject makes the endpoint answer with invalid_client
	reject bool
}

type recordedTokenRequest struct {
	form          url.Values
	query         url.Values
	authorization string
}

func (f *fakeTokenEndpoint) handler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.requests = append(f.requests, recordedTokenRequest{
		form:          r.PostForm,
		query:         r.URL.Query(),
		authorization: r.Header.Get("Authorization"),
	})
	reject := f.reject
	f.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	if reject {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"client authentication failed"}`))
		return
	}
	_, _ = w.Write([]byte(`{"access_token":"test-access-token","token_type":"Bearer","expires_in":3600}`))
}

func (f *fakeTokenEndpoint) last(t *testing.T) recordedTokenRequest {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	require.NotEmpty(t, f.requests)
	return f.requests[len(f.requests)-1]
}

func (f *fakeTokenEndpoint) setReject(reject bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reject = reject
}

func (f *fakeTokenEndpoint) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

func newTestOIDCProviderWithTokenEndpoint(t *testing.T, clientSecret string) (*CustomOIDCProvider, *fakeTokenEndpoint) {
	t.Helper()
	endpoint := &fakeTokenEndpoint{}
	server := httptest.NewServer(http.HandlerFunc(endpoint.handler))
	t.Cleanup(server.Close)

	return &CustomOIDCProvider{
		config: &oauth2.Config{
			ClientID:     "test-client-id",
			ClientSecret: clientSecret,
			RedirectURL:  "https://auth.example.com/callback",
			Scopes:       []string{"openid"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  server.URL + "/authorize",
				TokenURL: server.URL + "/token",
			},
		},
	}, endpoint
}

var testExchangeAssertionRequest = ClientAssertionRequest{
	ProviderID: "7f0c6a1e-1111-4222-8333-944445555666",
	ClientID:   "test-client-id",
	Audience:   "https://issuer.example.com",
}

func TestClientAssertionExchangeRequestShape(t *testing.T) {
	key := newTestRSAKey(t)
	config, _ := newTestAssertionConfig(t, key, "assertion-key")
	p, endpoint := newTestOIDCProviderWithTokenEndpoint(t, "")
	p.UseClientAssertion(NewClientAssertionCache(), config, testExchangeAssertionRequest, "custom:test")

	token, err := p.GetOAuthToken(context.Background(), "test-code", oauth2.VerifierOption("test-verifier"))
	require.NoError(t, err)
	assert.Equal(t, "test-access-token", token.AccessToken)

	req := endpoint.last(t)
	assert.Empty(t, req.authorization, "no Basic auth header")
	assert.Empty(t, req.query, "no credentials in the query string")
	assert.NotContains(t, req.form, "client_secret")
	assert.Equal(t, "test-client-id", req.form.Get("client_id"))
	assert.Equal(t, "authorization_code", req.form.Get("grant_type"))
	assert.Equal(t, "test-code", req.form.Get("code"))
	assert.Equal(t, "test-verifier", req.form.Get("code_verifier"))
	assert.Equal(t, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", req.form.Get("client_assertion_type"))

	parsed, err := jwt.Parse(req.form.Get("client_assertion"), func(*jwt.Token) (any, error) { return &key.PublicKey, nil },
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithAudience("https://issuer.example.com"),
		jwt.WithIssuer("test-client-id"),
		jwt.WithSubject("test-client-id"),
	)
	require.NoError(t, err)
	assert.Equal(t, "assertion-key", parsed.Header["kid"])
}

func TestClientAssertionExchangeReusesCachedAssertion(t *testing.T) {
	config, signs := newTestAssertionConfig(t, newTestRSAKey(t), "assertion-key")
	p, endpoint := newTestOIDCProviderWithTokenEndpoint(t, "")
	p.UseClientAssertion(NewClientAssertionCache(), config, testExchangeAssertionRequest, "custom:test")

	_, err := p.GetOAuthToken(context.Background(), "code-1")
	require.NoError(t, err)
	first := endpoint.last(t).form.Get("client_assertion")

	_, err = p.GetOAuthToken(context.Background(), "code-2")
	require.NoError(t, err)
	assert.Equal(t, first, endpoint.last(t).form.Get("client_assertion"))
	assert.EqualValues(t, 1, signs.Load())
}

func TestClientAssertionExchangeFailsClosed(t *testing.T) {
	t.Run("no signing key", func(t *testing.T) {
		p, endpoint := newTestOIDCProviderWithTokenEndpoint(t, "")
		p.UseClientAssertion(NewClientAssertionCache(), &conf.ClientAssertionConfiguration{}, testExchangeAssertionRequest, "custom:test")

		_, err := p.GetOAuthToken(context.Background(), "test-code")
		require.ErrorIs(t, err, errClientAssertionNotConfigured)
		assert.Equal(t, 0, endpoint.count(), "no token request is sent")
	})

	t.Run("signing error", func(t *testing.T) {
		sentinel := errors.New("kms unavailable")
		config, _ := newTestAssertionConfig(t, newTestRSAKey(t), "assertion-key")
		config.SigningKey = func(context.Context) (any, error) { return nil, sentinel }

		p, endpoint := newTestOIDCProviderWithTokenEndpoint(t, "")
		p.UseClientAssertion(NewClientAssertionCache(), config, testExchangeAssertionRequest, "custom:test")

		_, err := p.GetOAuthToken(context.Background(), "test-code")
		require.ErrorIs(t, err, sentinel)
		assert.Equal(t, 0, endpoint.count(), "no token request is sent")
	})
}

func TestClientAssertionExchangeInvalidClientDropsCache(t *testing.T) {
	config, signs := newTestAssertionConfig(t, newTestRSAKey(t), "assertion-key")
	clock := newTestClock()
	cache := newTestCache(clock)
	p, endpoint := newTestOIDCProviderWithTokenEndpoint(t, "")
	p.UseClientAssertion(cache, config, testExchangeAssertionRequest, "custom:test")

	endpoint.setReject(true)
	_, err := p.GetOAuthToken(context.Background(), "test-code")
	var retrieveErr *oauth2.RetrieveError
	require.ErrorAs(t, err, &retrieveErr)
	assert.Equal(t, "invalid_client", retrieveErr.ErrorCode)
	rejected := endpoint.last(t).form.Get("client_assertion")

	// the error does not carry the assertion
	assert.NotContains(t, err.Error(), rejected)

	// the next exchange signs a new assertion instead of reusing the rejected one
	endpoint.setReject(false)
	clock.advance(time.Second) // so the new assertion differs
	_, err = p.GetOAuthToken(context.Background(), "test-code")
	require.NoError(t, err)
	assert.NotEqual(t, rejected, endpoint.last(t).form.Get("client_assertion"))
	assert.EqualValues(t, 2, signs.Load())
}

func TestClientAssertionExchangeOtherErrorsKeepCache(t *testing.T) {
	config, signs := newTestAssertionConfig(t, newTestRSAKey(t), "assertion-key")
	p, _ := newTestOIDCProviderWithTokenEndpoint(t, "")
	cache := NewClientAssertionCache()
	p.UseClientAssertion(cache, config, testExchangeAssertionRequest, "custom:test")

	// warm the cache, then point the provider at an endpoint that returns invalid_grant
	_, err := p.GetOAuthToken(context.Background(), "code-1")
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	t.Cleanup(server.Close)
	p.config.Endpoint.TokenURL = server.URL

	_, err = p.GetOAuthToken(context.Background(), "code-2")
	require.Error(t, err)
	_, err = p.GetOAuthToken(context.Background(), "code-3")
	require.Error(t, err)
	assert.EqualValues(t, 1, signs.Load(), "invalid_grant does not drop the cached assertion")
}

func TestClientSecretExchangeUnchanged(t *testing.T) {
	p, endpoint := newTestOIDCProviderWithTokenEndpoint(t, "test-client-secret")

	_, err := p.GetOAuthToken(context.Background(), "test-code")
	require.NoError(t, err)

	req := endpoint.last(t)
	assert.NotContains(t, req.form, "client_assertion")
	assert.NotContains(t, req.form, "client_assertion_type")
	// x/oauth2 auto-detects the auth style and tries a Basic auth header first
	user, pass, ok := (&http.Request{Header: http.Header{"Authorization": {req.authorization}}}).BasicAuth()
	require.True(t, ok)
	assert.Equal(t, "test-client-id", user)
	assert.Equal(t, "test-client-secret", pass)
}
