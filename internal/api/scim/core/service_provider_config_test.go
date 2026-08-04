package core

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewServiceProviderConfig(t *testing.T) {
	t.Run("advertises the schemes the caller declares", func(t *testing.T) {
		schemes := []AuthenticationScheme{OAuthBearerToken().AsPrimary()}

		config := NewServiceProviderConfig("", schemes)

		require.Equal(t, []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"}, config.Schemas)
		require.Equal(t, schemes, config.AuthenticationSchemes)
	})

	t.Run("identifies itself with resource metadata", func(t *testing.T) {
		baseURL := "http://localhost:9999/scim/v2"
		config := NewServiceProviderConfig(baseURL, nil)

		require.Equal(t, "ServiceProviderConfig", config.Meta.ResourceType)
		require.Equal(t, baseURL+"/ServiceProviderConfig", config.Meta.Location)
	})

	t.Run("supports none of the optional protocol features", func(t *testing.T) {
		config := NewServiceProviderConfig("", nil)

		require.False(t, config.Patch.Supported)
		require.False(t, config.Bulk.Supported)
		require.False(t, config.Filter.Supported)
		require.False(t, config.ChangePassword.Supported)
		require.False(t, config.Sort.Supported)
		require.False(t, config.ETag.Supported)
	})

	t.Run("serializes authenticationSchemes as an array", func(t *testing.T) {
		body, err := json.Marshal(NewServiceProviderConfig("", nil))

		require.NoError(t, err)
		require.Contains(t, string(body), `"authenticationSchemes":[]`)
	})
}

func TestAuthenticationScheme(t *testing.T) {
	t.Run("OAuthBearerToken", func(t *testing.T) {
		scheme := OAuthBearerToken()

		require.Equal(t, "oauthbearertoken", scheme.Type)
		require.Equal(t, "OAuth Bearer Token", scheme.Name)
		require.Equal(t, "Authentication scheme using the OAuth Bearer Token Standard", scheme.Description)
		require.Equal(t, "http://www.rfc-editor.org/info/rfc6750", scheme.SpecURI)
	})

	t.Run("AsPrimary", func(t *testing.T) {
		assert.False(t, OAuthBearerToken().Primary)
		assert.True(t, OAuthBearerToken().AsPrimary().Primary)
	})
}
