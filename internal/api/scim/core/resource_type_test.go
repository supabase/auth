package core

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResourceType(t *testing.T) {
	r := ResourceType{Name: "Resource", Endpoint: "/Resources"}

	t.Run("Meta", func(t *testing.T) {
		baseURL := "http://localhost:9999/scim/v2"

		t.Run("locates a resource that is its own endpoint", func(t *testing.T) {
			meta := r.Meta(baseURL)

			require.Equal(t, ResourceTypeName("Resource"), meta.ResourceType)
			require.Equal(t, baseURL+"/Resources", meta.Location)
			require.Zero(t, meta.Created)
			require.Zero(t, meta.LastModified)
		})
	})
}
