package provider

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
)

func TestNewKakaoProviderScopes(t *testing.T) {
	config := conf.OAuthProviderConfiguration{
		Enabled:     true,
		ClientID:    []string{"client-id"},
		Secret:      "secret",
		RedirectURI: "https://project.supabase.co/auth/v1/callback",
	}

	t.Run("requests email by default", func(t *testing.T) {
		p, err := NewKakaoProvider(config, "")
		require.NoError(t, err)

		kakao, ok := p.(*kakaoProvider)
		require.True(t, ok)
		require.Equal(t, []string{
			"account_email",
			"profile_image",
			"profile_nickname",
		}, kakao.Scopes)
	})

	t.Run("omits email when email is optional", func(t *testing.T) {
		config := config
		config.EmailOptional = true

		p, err := NewKakaoProvider(config, "")
		require.NoError(t, err)

		kakao, ok := p.(*kakaoProvider)
		require.True(t, ok)
		require.Equal(t, []string{
			"profile_image",
			"profile_nickname",
		}, kakao.Scopes)
	})

	t.Run("allows custom scopes to opt back into email", func(t *testing.T) {
		config := config
		config.EmailOptional = true

		p, err := NewKakaoProvider(config, "account_email")
		require.NoError(t, err)

		kakao, ok := p.(*kakaoProvider)
		require.True(t, ok)
		require.Equal(t, []string{
			"profile_image",
			"profile_nickname",
			"account_email",
		}, kakao.Scopes)
	})
}
