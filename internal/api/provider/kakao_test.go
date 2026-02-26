package provider

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
)

func TestNewKakaoProvider_DefaultScopes(t *testing.T) {
	ext := conf.OAuthProviderConfiguration{
		Enabled:     true,
		ClientID:    []string{"test-client-id"},
		Secret:      "test-secret",
		RedirectURI: "http://localhost:9999/callback",
	}

	p, err := NewKakaoProvider(ext, "")
	require.NoError(t, err)

	kakao, ok := p.(*kakaoProvider)
	require.True(t, ok)
	assert.Equal(t, []string{"profile_image", "profile_nickname"}, kakao.Config.Scopes)
	assert.NotContains(t, kakao.Config.Scopes, "account_email")
}

func TestNewKakaoProvider_AppendsCustomScopes(t *testing.T) {
	ext := conf.OAuthProviderConfiguration{
		Enabled:     true,
		ClientID:    []string{"test-client-id"},
		Secret:      "test-secret",
		RedirectURI: "http://localhost:9999/callback",
	}

	p, err := NewKakaoProvider(ext, "account_email")
	require.NoError(t, err)

	kakao, ok := p.(*kakaoProvider)
	require.True(t, ok)
	assert.Equal(t, []string{"profile_image", "profile_nickname", "account_email"}, kakao.Config.Scopes)
}
