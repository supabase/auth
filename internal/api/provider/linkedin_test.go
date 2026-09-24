package provider

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
)

func TestNewLinkedinProviderEndpoints(t *testing.T) {
	p, err := NewLinkedinProvider(conf.OAuthProviderConfiguration{
		Enabled:     true,
		ClientID:    []string{"client-id"},
		Secret:      "secret",
		RedirectURI: "https://project.supabase.co/auth/v1/callback",
	}, "")
	require.NoError(t, err)

	linkedin := p.(*linkedinProvider)
	assert.Equal(t, "https://www.linkedin.com/oauth/v2/authorization", linkedin.Endpoint.AuthURL)
	assert.Equal(t, "https://www.linkedin.com/oauth/v2/accessToken", linkedin.Endpoint.TokenURL)
	assert.Equal(t, "https://api.linkedin.com", linkedin.APIPath)
}
