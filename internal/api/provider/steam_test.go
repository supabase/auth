package provider

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
)

func TestSteamProvider(t *testing.T) {
	provider, err := NewSteamProvider(conf.OAuthProviderConfiguration{
		Realm: "http://localhost:9999",
	})
	require.NoError(t, err)

	authURL := provider.GetAuthorizationURL("test-state")
	require.Contains(t, authURL, "steamcommunity.com/openid/login")
	require.Contains(t, authURL, "openid.mode=checkid_setup")
	require.Contains(t, authURL, "openid.realm=http://localhost:9999")

	u, err := url.Parse(authURL)
	require.NoError(t, err)
	require.Equal(t, "http://specs.openid.net/auth/2.0/identifier_select", u.Query().Get("openid.claimed_id"))
} 