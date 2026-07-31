package core

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewMeta(t *testing.T) {
	baseURL := "http://localhost:9999/scim/v2"

	t.Run("locates a resource that is its own endpoint", func(t *testing.T) {
		meta := NewMeta(baseURL, ResourceTypeServiceProviderConfig, EndpointServiceProviderConfig, "")

		require.Equal(t, ResourceTypeServiceProviderConfig, meta.ResourceType)
		require.Equal(t, baseURL+"/ServiceProviderConfig", meta.Location)
	})

	t.Run("locates one resource of a collection", func(t *testing.T) {
		meta := NewMeta(baseURL, ResourceTypeUser, EndpointUsers, "2819c223-7f76-453a-919d-413861904646")

		require.Equal(t, ResourceTypeUser, meta.ResourceType)
		require.Equal(t, baseURL+"/Users/2819c223-7f76-453a-919d-413861904646", meta.Location)
	})
}

func TestMeta(t *testing.T) {
	t.Run("serializes to JSON correctly", func(t *testing.T) {
		body, err := json.Marshal(Meta{
			ResourceType: ResourceTypeServiceProviderConfig,
			Location:     "http://localhost:9999/scim/v2/ServiceProviderConfig",
		})

		require.NoError(t, err)
		require.JSONEq(t, `{
			"resourceType": "ServiceProviderConfig",
			"location": "http://localhost:9999/scim/v2/ServiceProviderConfig"
		}`, string(body))
	})

	t.Run("omits the location when it is empty", func(t *testing.T) {
		body, err := json.Marshal(Meta{ResourceType: ResourceTypeServiceProviderConfig})

		require.NoError(t, err)
		require.JSONEq(t, `{"resourceType": "ServiceProviderConfig"}`, string(body))
	})
}
