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

		t.Run("declares no schema extensions until it is extended", func(t *testing.T) {
			body, err := json.Marshal(NewResourceType(baseURL, KindUser, schema))

			require.NoError(t, err)
			require.NotContains(t, string(body), "schemaExtensions")
		})
	})

	t.Run("Extend", func(t *testing.T) {
		schema := NewSchema(baseURL, KindUser)
		enterprise := SchemaExtension{Schema: SchemaEnterpriseUser, Required: true}

		t.Run("keeps the extensions of an earlier call", func(t *testing.T) {
			resourceType := NewResourceType(baseURL, KindUser, schema).Extend(enterprise)

			require.Same(t, resourceType, resourceType.Extend(SchemaExtension{Schema: SchemaGroup}))
			require.Equal(t, []SchemaExtension{enterprise, {Schema: SchemaGroup}}, resourceType.SchemaExtensions)
		})
	})

	t.Run("Kind", func(t *testing.T) {
		t.Run("names the kind and endpoint it was built from", func(t *testing.T) {
			resourceType := NewResourceType(baseURL, KindUser, NewSchema(baseURL, KindUser))

			kind := resourceType.Kind()

			require.Equal(t, KindUser.Name, kind.Name)
			require.Equal(t, KindUser.Endpoint, kind.Endpoint)
			require.Equal(t, baseURL+"/Users", kind.Location(baseURL))
		})
	})
}
