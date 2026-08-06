package provider

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
)

func TestNewNHSCIS2Provider(t *testing.T) {
	t.Run("valid configuration", func(t *testing.T) {
		cfg := conf.OAuthProviderConfiguration{
			ClientID:    []string{"test-client-id"},
			Secret:      "test-secret",
			RedirectURI: "https://example.com/callback",
			URL:         "https://am.nhsidentity.spineservices.nhs.uk",
			Enabled:     true,
		}

		p, err := NewNHSCIS2Provider(cfg, "")
		require.NoError(t, err)
		require.NotNil(t, p)

		provider := p.(*nhsCIS2Provider)
		assert.Equal(t, "test-client-id", provider.Config.ClientID)
		assert.Equal(t, "test-secret", provider.Config.ClientSecret)
		assert.Equal(t, "https://example.com/callback", provider.Config.RedirectURL)
		assert.Contains(t, provider.Config.Scopes, "openid")
		assert.Contains(t, provider.Config.Scopes, "profile")
		assert.Contains(t, provider.Config.Scopes, "email")
	})

	t.Run("valid configuration with custom scopes", func(t *testing.T) {
		cfg := conf.OAuthProviderConfiguration{
			ClientID:    []string{"test-client-id"},
			Secret:      "test-secret",
			RedirectURI: "https://example.com/callback",
			URL:         "https://am.nhsidentity.spineservices.nhs.uk",
			Enabled:     true,
		}

		p, err := NewNHSCIS2Provider(cfg, "nationalrbacaccess,associatedorgs")
		require.NoError(t, err)
		require.NotNil(t, p)

		provider := p.(*nhsCIS2Provider)
		assert.Contains(t, provider.Config.Scopes, "openid")
		assert.Contains(t, provider.Config.Scopes, "profile")
		assert.Contains(t, provider.Config.Scopes, "email")
		assert.Contains(t, provider.Config.Scopes, "nationalrbacaccess")
		assert.Contains(t, provider.Config.Scopes, "associatedorgs")
	})

	t.Run("default host when URL not provided", func(t *testing.T) {
		cfg := conf.OAuthProviderConfiguration{
			ClientID:    []string{"test-client-id"},
			Secret:      "test-secret",
			RedirectURI: "https://example.com/callback",
			URL:         "",
			Enabled:     true,
		}

		p, err := NewNHSCIS2Provider(cfg, "")
		require.NoError(t, err)
		require.NotNil(t, p)

		provider := p.(*nhsCIS2Provider)
		assert.Equal(t, "https://"+defaultNHSCIS2Host, provider.Host)
	})

	t.Run("custom host URL", func(t *testing.T) {
		cfg := conf.OAuthProviderConfiguration{
			ClientID:    []string{"test-client-id"},
			Secret:      "test-secret",
			RedirectURI: "https://example.com/callback",
			URL:         "https://custom.nhs.example.com",
			Enabled:     true,
		}

		p, err := NewNHSCIS2Provider(cfg, "")
		require.NoError(t, err)
		require.NotNil(t, p)

		provider := p.(*nhsCIS2Provider)
		assert.Equal(t, "https://custom.nhs.example.com", provider.Host)
	})

	t.Run("missing client ID", func(t *testing.T) {
		cfg := conf.OAuthProviderConfiguration{
			ClientID:    []string{},
			Secret:      "test-secret",
			RedirectURI: "https://example.com/callback",
			URL:         "https://am.nhsidentity.spineservices.nhs.uk",
			Enabled:     true,
		}

		p, err := NewNHSCIS2Provider(cfg, "")
		require.Error(t, err)
		require.Nil(t, p)
		assert.Contains(t, err.Error(), "client ID")
	})

	t.Run("missing secret", func(t *testing.T) {
		cfg := conf.OAuthProviderConfiguration{
			ClientID:    []string{"test-client-id"},
			Secret:      "",
			RedirectURI: "https://example.com/callback",
			URL:         "https://am.nhsidentity.spineservices.nhs.uk",
			Enabled:     true,
		}

		p, err := NewNHSCIS2Provider(cfg, "")
		require.Error(t, err)
		require.Nil(t, p)
		assert.Contains(t, err.Error(), "secret")
	})

	t.Run("missing redirect URI", func(t *testing.T) {
		cfg := conf.OAuthProviderConfiguration{
			ClientID:    []string{"test-client-id"},
			Secret:      "test-secret",
			RedirectURI: "",
			URL:         "https://am.nhsidentity.spineservices.nhs.uk",
			Enabled:     true,
		}

		p, err := NewNHSCIS2Provider(cfg, "")
		require.Error(t, err)
		require.Nil(t, p)
		assert.Contains(t, err.Error(), "redirect")
	})

	t.Run("provider not enabled", func(t *testing.T) {
		cfg := conf.OAuthProviderConfiguration{
			ClientID:    []string{"test-client-id"},
			Secret:      "test-secret",
			RedirectURI: "https://example.com/callback",
			URL:         "https://am.nhsidentity.spineservices.nhs.uk",
			Enabled:     false,
		}

		p, err := NewNHSCIS2Provider(cfg, "")
		require.Error(t, err)
		require.Nil(t, p)
		assert.Contains(t, err.Error(), "not enabled")
	})

	t.Run("correct OAuth endpoints", func(t *testing.T) {
		cfg := conf.OAuthProviderConfiguration{
			ClientID:    []string{"test-client-id"},
			Secret:      "test-secret",
			RedirectURI: "https://example.com/callback",
			URL:         "https://am.nhsidentity.spineservices.nhs.uk",
			Enabled:     true,
		}

		p, err := NewNHSCIS2Provider(cfg, "")
		require.NoError(t, err)
		require.NotNil(t, p)

		provider := p.(*nhsCIS2Provider)
		expectedAuthURL := "https://am.nhsidentity.spineservices.nhs.uk" + nhsCIS2AuthPath
		expectedTokenURL := "https://am.nhsidentity.spineservices.nhs.uk" + nhsCIS2TokenPath

		assert.Equal(t, expectedAuthURL, provider.Config.Endpoint.AuthURL)
		assert.Equal(t, expectedTokenURL, provider.Config.Endpoint.TokenURL)
	})
}

func TestNHSCIS2UserUnmarshalJSON(t *testing.T) {
	t.Run("full user data", func(t *testing.T) {
		jsonData := `{
			"sub": "user-123",
			"email": "doctor@nhs.net",
			"email_verified": true,
			"name": "Dr John Smith",
			"given_name": "John",
			"family_name": "Smith",
			"preferred_username": "jsmith",
			"uid": "123456789012",
			"nhsid_nrbac_roles": "R8000:G8000:R8001",
			"id_assurance_level": "3",
			"authentication_assurance_level": "2",
			"selected_roleid": "555254240100"
		}`

		var u nhsCIS2User
		err := json.Unmarshal([]byte(jsonData), &u)
		require.NoError(t, err)

		assert.Equal(t, "user-123", u.Sub)
		assert.Equal(t, "doctor@nhs.net", u.Email)
		assert.Equal(t, true, u.EmailVerified)
		assert.Equal(t, "Dr John Smith", u.Name)
		assert.Equal(t, "John", u.GivenName)
		assert.Equal(t, "Smith", u.FamilyName)
		assert.Equal(t, "jsmith", u.PreferredUsername)
		assert.Equal(t, "123456789012", u.UID)
		assert.Equal(t, "R8000:G8000:R8001", u.NHSNumber)
		assert.Equal(t, "3", u.IDAssuranceLevel)
		assert.Equal(t, "2", u.AuthenticationLevel)
		assert.Equal(t, "555254240100", u.OrganizationCode)
	})

	t.Run("minimal user data", func(t *testing.T) {
		jsonData := `{
			"sub": "user-456",
			"email": "nurse@nhs.net"
		}`

		var u nhsCIS2User
		err := json.Unmarshal([]byte(jsonData), &u)
		require.NoError(t, err)

		assert.Equal(t, "user-456", u.Sub)
		assert.Equal(t, "nurse@nhs.net", u.Email)
		assert.Equal(t, false, u.EmailVerified)
		assert.Equal(t, "", u.Name)
		assert.Equal(t, "", u.GivenName)
		assert.Equal(t, "", u.FamilyName)
	})

	t.Run("preserves raw claims", func(t *testing.T) {
		jsonData := `{
			"sub": "user-789",
			"email": "admin@nhs.net",
			"custom_claim_1": "value1",
			"custom_claim_2": 42,
			"nested_claim": {"key": "value"}
		}`

		var u nhsCIS2User
		err := json.Unmarshal([]byte(jsonData), &u)
		require.NoError(t, err)

		assert.Equal(t, "user-789", u.Sub)
		assert.Equal(t, "admin@nhs.net", u.Email)
		assert.Equal(t, "value1", u.RawClaims["custom_claim_1"])
		assert.Equal(t, float64(42), u.RawClaims["custom_claim_2"])
		nested := u.RawClaims["nested_claim"].(map[string]interface{})
		assert.Equal(t, "value", nested["key"])
	})

	t.Run("invalid JSON", func(t *testing.T) {
		jsonData := `{invalid json}`

		var u nhsCIS2User
		err := json.Unmarshal([]byte(jsonData), &u)
		require.Error(t, err)
	})
}

func TestNHSCIS2ProviderEndpoints(t *testing.T) {
	t.Run("auth endpoint path", func(t *testing.T) {
		assert.Equal(t,
			"/openam/oauth2/realms/root/realms/NHSIdentity/realms/Healthcare/authorize",
			nhsCIS2AuthPath,
		)
	})

	t.Run("token endpoint path", func(t *testing.T) {
		assert.Equal(t,
			"/openam/oauth2/realms/root/realms/NHSIdentity/realms/Healthcare/access_token",
			nhsCIS2TokenPath,
		)
	})

	t.Run("userinfo endpoint path", func(t *testing.T) {
		assert.Equal(t,
			"/openam/oauth2/realms/root/realms/NHSIdentity/realms/Healthcare/userinfo",
			nhsCIS2UserInfoPath,
		)
	})
}

func TestNHSCIS2DefaultHost(t *testing.T) {
	assert.Equal(t, "am.nhsidentity.spineservices.nhs.uk", defaultNHSCIS2Host)
}
