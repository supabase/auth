package core

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResourceType(t *testing.T) {
	baseURL := "http://localhost:9999/scim/v2"

	t.Run("NewResourceType", func(t *testing.T) {
		schema := NewSchema(baseURL, KindUser).Describe("User Account")

		resourceType := NewResourceType(baseURL, KindUser, schema)

		t.Run("takes its identity and description from the schema", func(t *testing.T) {
			require.Equal(t, KindUser.Name, resourceType.ID)
			require.Equal(t, KindUser.Name, resourceType.Name)
			require.Equal(t, "User Account", resourceType.Description)
			require.Equal(t, SchemaUser, resourceType.Schema)
		})

		t.Run("locates itself under the ResourceTypes endpoint", func(t *testing.T) {
			require.Equal(t, KindResourceType.Name, resourceType.Meta.ResourceType)
			require.Equal(t, baseURL+"/ResourceTypes/User", resourceType.Meta.Location)
		})

		t.Run("declares the schema extensions it was given", func(t *testing.T) {
			extended := NewResourceType(baseURL, KindUser, schema).
				Extend(SchemaExtension{Schema: SchemaEnterpriseUser, Required: true})

			body, err := json.Marshal(extended)

			require.NoError(t, err)
			require.Contains(t, string(body),
				`"schemaExtensions":[{"schema":"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User","required":true}]`)
		})
	})
}
