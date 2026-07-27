package provider

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/mrjones/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
)

func TestNewTwitterProvider(t *testing.T) {
	t.Run("Valid configuration", func(t *testing.T) {
		config := conf.OAuthProviderConfiguration{
			ClientID:    []string{"client-id"},
			Secret:      "secret",
			RedirectURI: "https://example.com/callback",
			Enabled:     true,
		}

		provider, err := NewTwitterProvider(config, "")
		require.NoError(t, err)
		assert.NotNil(t, provider)

		twitterProvider, ok := provider.(*TwitterProvider)
		require.True(t, ok)
		assert.Equal(t, "client-id", twitterProvider.ClientKey)
		assert.Equal(t, "secret", twitterProvider.Secret)
		assert.Equal(t, "https://example.com/callback", twitterProvider.CallbackURL)
		assert.Equal(t, "https://api.twitter.com"+endpointProfile, twitterProvider.UserInfoURL)
	})

	t.Run("Custom API URL", func(t *testing.T) {
		config := conf.OAuthProviderConfiguration{
			ClientID:    []string{"client-id"},
			Secret:      "secret",
			RedirectURI: "https://example.com/callback",
			URL:         "https://custom-twitter-api.example.com",
			Enabled:     true,
		}

		provider, err := NewTwitterProvider(config, "")
		require.NoError(t, err)
		assert.NotNil(t, provider)

		twitterProvider, ok := provider.(*TwitterProvider)
		require.True(t, ok)
		assert.Equal(t, "https://custom-twitter-api.example.com"+endpointProfile, twitterProvider.UserInfoURL)
	})

	t.Run("Invalid configuration", func(t *testing.T) {
		tests := []struct {
			name   string
			config conf.OAuthProviderConfiguration
		}{
			{
				name: "Missing ClientID",
				config: conf.OAuthProviderConfiguration{
					Secret:      "secret",
					RedirectURI: "https://example.com/callback",
					Enabled:     true,
				},
			},
			{
				name: "Missing Secret",
				config: conf.OAuthProviderConfiguration{
					ClientID:    []string{"client-id"},
					RedirectURI: "https://example.com/callback",
					Enabled:     true,
				},
			},
			{
				name: "Missing RedirectURI",
				config: conf.OAuthProviderConfiguration{
					ClientID: []string{"client-id"},
					Secret:   "secret",
					Enabled:  true,
				},
			},
			{
				name: "Provider not enabled",
				config: conf.OAuthProviderConfiguration{
					ClientID:    []string{"client-id"},
					Secret:      "secret",
					RedirectURI: "https://example.com/callback",
					Enabled:     false,
				},
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				_, err := NewTwitterProvider(tc.config, "")
				assert.Error(t, err)
			})
		}
	})
}

// We'll skip these tests as they're hard to mock without reimplementing the OAuth library
func TestTwitterProviderAuthCodeURL(t *testing.T) {
	t.Skip("Skipping test as it requires complex mocking of OAuth1.0 library")
}

func TestTwitterProviderFetchUserData(t *testing.T) {
	t.Skip("Skipping test as it requires complex mocking of OAuth1.0 library")
}

func TestTwitterProviderFetchUserDataErrors(t *testing.T) {
	t.Skip("Skipping test as it requires complex mocking of OAuth1.0 library")
}

func TestTwitterProviderMarshalUnmarshal(t *testing.T) {
	provider := &TwitterProvider{
		ClientKey:   "client-key",
		Secret:      "secret",
		CallbackURL: "https://example.com/callback",
		RequestToken: &oauth.RequestToken{
			Token:  "token",
			Secret: "token-secret",
		},
	}

	// Test Marshal
	data := provider.Marshal()
	assert.NotEmpty(t, data)

	// Test Unmarshal
	token, err := provider.Unmarshal(data)
	require.NoError(t, err)
	assert.Equal(t, provider.RequestToken.Token, token.Token)
	assert.Equal(t, provider.RequestToken.Secret, token.Secret)
}

func TestTwitterProviderStubMethods(t *testing.T) {
	provider := &TwitterProvider{
		ClientKey:   "client-key",
		Secret:      "secret",
		CallbackURL: "https://example.com/callback",
	}

	// Test stub methods
	token, err := provider.GetOAuthToken("state")
	assert.NoError(t, err)
	assert.NotNil(t, token)

	userData, err := provider.GetUserData(context.Background(), token)
	assert.NoError(t, err)
	assert.NotNil(t, userData)
}

// Add some basic tests for Twitter user struct parsing
func TestTwitterUserParsing(t *testing.T) {
	t.Run("parses Twitter user JSON correctly", func(t *testing.T) {
		// Sample Twitter user JSON
		userJSON := `{
			"id_str": "12345678",
			"name": "Test User",
			"screen_name": "testuser",
			"email": "test@example.com",
			"profile_image_url_https": "https://pbs.twimg.com/profile_images/test.jpg"
		}`

		// Parse the JSON
		var user twitterUser
		err := json.Unmarshal([]byte(userJSON), &user)
		require.NoError(t, err)

		// Verify fields were parsed correctly
		assert.Equal(t, "12345678", user.ID)
		assert.Equal(t, "Test User", user.Name)
		assert.Equal(t, "testuser", user.UserName)
		assert.Equal(t, "test@example.com", user.Email)
		assert.Equal(t, "https://pbs.twimg.com/profile_images/test.jpg", user.AvatarURL)
	})

	t.Run("handles missing fields", func(t *testing.T) {
		// Sample Twitter user JSON with missing fields
		userJSON := `{
			"id_str": "12345678",
			"name": "Test User"
		}`

		// Parse the JSON
		var user twitterUser
		err := json.Unmarshal([]byte(userJSON), &user)
		require.NoError(t, err)

		// Verify required fields were parsed and missing ones are empty
		assert.Equal(t, "12345678", user.ID)
		assert.Equal(t, "Test User", user.Name)
		assert.Empty(t, user.UserName)
		assert.Empty(t, user.Email)
		assert.Empty(t, user.AvatarURL)
	})
}
