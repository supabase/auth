package provider

import (
	"context"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
)

func TestNewLinkedinOIDCProviderEndpoints(t *testing.T) {
	cache := NewOIDCProviderCache(time.Hour)
	// Seed the cache so the constructor does not fetch LinkedIn's discovery document.
	cache.putEntry(IssuerLinkedin, (&oidc.ProviderConfig{IssuerURL: IssuerLinkedin}).NewProvider(context.Background()))

	cases := []struct {
		name             string
		url              string
		expectedAuthURL  string
		expectedTokenURL string
	}{
		{
			name:             "defaults to www.linkedin.com",
			url:              "",
			expectedAuthURL:  "https://www.linkedin.com/oauth/v2/authorization",
			expectedTokenURL: "https://www.linkedin.com/oauth/v2/accessToken",
		},
		{
			name:             "custom url overrides the host",
			url:              "https://linkedin.example.com/",
			expectedAuthURL:  "https://linkedin.example.com/oauth/v2/authorization",
			expectedTokenURL: "https://linkedin.example.com/oauth/v2/accessToken",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, err := NewLinkedinOIDCProvider(context.Background(), conf.OAuthProviderConfiguration{
				Enabled:     true,
				ClientID:    []string{"client-id"},
				Secret:      "secret",
				RedirectURI: "https://project.supabase.co/auth/v1/callback",
				URL:         c.url,
			}, "", cache)
			require.NoError(t, err)

			endpoint := p.(*linkedinOIDCProvider).Endpoint
			assert.Equal(t, c.expectedAuthURL, endpoint.AuthURL)
			assert.Equal(t, c.expectedTokenURL, endpoint.TokenURL)
		})
	}
}
