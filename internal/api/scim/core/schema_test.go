package core

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSchema(t *testing.T) {
	baseURL := "http://localhost:9999/scim/v2"

	t.Run("NewSchema", func(t *testing.T) {
		schema := NewSchema(baseURL, KindUser)

		t.Run("identifies itself by the URI of the kind it describes", func(t *testing.T) {
			require.Equal(t, []SchemaURI{SchemaSchema}, schema.Schemas)
			require.Equal(t, SchemaUser, schema.ID)
			require.Equal(t, KindUser.Name, schema.Name)
		})

		t.Run("locates itself by URI under the Schemas endpoint", func(t *testing.T) {
			require.Equal(t, KindSchema.Name, schema.Meta.ResourceType)
			require.Equal(t, baseURL+"/Schemas/urn:ietf:params:scim:schemas:core:2.0:User", schema.Meta.Location)
		})

		t.Run("carries no timestamps because a schema never changes", func(t *testing.T) {
			created, updated := schema.Timestamps()

			require.Zero(t, created)
			require.Zero(t, updated)
			require.Zero(t, schema.Meta.Created)
			require.Zero(t, schema.Meta.LastModified)
		})
	})

	t.Run("Describe", func(t *testing.T) {
		schema := NewSchema(baseURL, KindUser)

		require.Same(t, schema, schema.Describe("User Account"))
		assert.Equal(t, "User Account", schema.Description)
	})

	t.Run("With", func(t *testing.T) {
		userName := NewAttribute("userName", TypeString, "A unique identifier for the user.")
		schema := NewSchema(baseURL, KindUser)

		require.Same(t, schema, schema.With(userName))
		assert.Equal(t, []*Attribute{userName}, schema.Attributes)
	})

	t.Run("serializes to JSON correctly", func(t *testing.T) {
		schema := NewSchema(baseURL, KindUser).
			Describe("User Account").
			With(NewAttribute("userName", TypeString, "A unique identifier for the user.").AsRequired())

		body, err := json.Marshal(schema)

		require.NoError(t, err)
		require.JSONEq(t, `{
			"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Schema"],
			"id": "urn:ietf:params:scim:schemas:core:2.0:User",
			"name": "User",
			"description": "User Account",
			"attributes": [{
				"name": "userName",
				"type": "string",
				"multiValued": false,
				"description": "A unique identifier for the user.",
				"required": true,
				"caseExact": false,
				"mutability": "readWrite",
				"returned": "default",
				"uniqueness": "none"
			}],
			"meta": {
				"resourceType": "Schema",
				"location": "http://localhost:9999/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User"
			}
		}`, string(body))
	})
}
