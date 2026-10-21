package provider

import (
	"context"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
)

func linkedinOIDCTestConfig(url string) conf.OAuthProviderConfiguration {
	return conf.OAuthProviderConfiguration{
		Enabled:     true,
		ClientID:    []string{"client-id"},
		Secret:      "client-secret",
		RedirectURI: "https://project.supabase.co/auth/v1/callback",
		URL:         url,
	}
}

// newLinkedinOIDCTestCache seeds the provider cache for IssuerLinkedin so
// NewLinkedinOIDCProvider never fetches the discovery document over the network.
func newLinkedinOIDCTestCache() *OIDCProviderCache {
	cache := NewOIDCProviderCache(time.Hour)
	cache.putEntry(IssuerLinkedin, &oidc.Provider{})
	return cache
}

func TestNewLinkedinOIDCProviderUsesDocumentedOAuthEndpoints(t *testing.T) {
	p, err := NewLinkedinOIDCProvider(
		context.Background(),
		linkedinOIDCTestConfig(""),
		"",
		newLinkedinOIDCTestCache(),
	)
	require.NoError(t, err)

	lp, ok := p.(*linkedinOIDCProvider)
	require.True(t, ok)
	require.Equal(t, "https://www.linkedin.com/oauth/v2/authorization", lp.Endpoint.AuthURL)
	require.Equal(t, "https://www.linkedin.com/oauth/v2/accessToken", lp.Endpoint.TokenURL)
	require.Equal(t, "https://api.linkedin.com", lp.APIPath)
}

func TestNewLinkedinOIDCProviderHostOverride(t *testing.T) {
	p, err := NewLinkedinOIDCProvider(
		context.Background(),
		linkedinOIDCTestConfig("https://linkedin.example.com"),
		"",
		newLinkedinOIDCTestCache(),
	)
	require.NoError(t, err)

	lp, ok := p.(*linkedinOIDCProvider)
	require.True(t, ok)
	require.Equal(t, "https://linkedin.example.com/oauth/v2/authorization", lp.Endpoint.AuthURL)
	require.Equal(t, "https://linkedin.example.com/oauth/v2/accessToken", lp.Endpoint.TokenURL)
	require.Equal(t, "https://linkedin.example.com", lp.APIPath)
}
