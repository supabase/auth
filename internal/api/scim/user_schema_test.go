package scim

import (
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api/scim/core"
)

// commonAttributes belong to every resource under RFC 7643, Section 3.1, rather
// than to a schema. The RFC's own User schema in Section 8.7.1 does not list
// them either.
var commonAttributes = []string{"schemas", "id", "externalId", "meta"}

// fullUser has every field set, so that marshalling it names every attribute a
// User can serve. Fields tagged omitempty or omitzero would otherwise vanish.
func fullUser() *core.User {
	active := true

	return &core.User{
		Schemas:    []core.SchemaURI{core.SchemaUser},
		ID:         "2819c223-7f76-453a-919d-413861904646",
		ExternalID: "701984",
		UserName:   "bjensen@example.com",
		Name:       core.Name{Formatted: "Ms. Barbara J Jensen, III", FamilyName: "Jensen", GivenName: "Barbara", MiddleName: "Jane"},
		Emails:     []core.Email{{Value: "bjensen@example.com", Primary: true}},
		Active:     &active,
		Meta: core.Meta{
			ResourceType: core.KindUser.Name,
			Created:      time.Now(),
			LastModified: time.Now(),
			Location:     "http://localhost:9999/scim/v2/Users/2819c223-7f76-453a-919d-413861904646",
		},
	}
}

// jsonFields are the attribute names a value serves on the wire.
func jsonFields(t *testing.T, value any) []string {
	t.Helper()

	body, err := json.Marshal(value)
	require.NoError(t, err)

	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(body, &fields))

	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func attributeNames(attributes []*core.Attribute) []string {
	names := make([]string, 0, len(attributes))
	for _, attribute := range attributes {
		names = append(names, attribute.Name)
	}
	slices.Sort(names)
	return names
}

func subAttributesOf(t *testing.T, attributes []*core.Attribute, name string) []*core.Attribute {
	t.Helper()

	for _, attribute := range attributes {
		if attribute.Name == name {
			return attribute.SubAttributes
		}
	}
	t.Fatalf("%q is not declared", name)
	return nil
}

// TestUserSchemaDescribesTheResource is what keeps /Schemas honest. A client
// reads it to learn what it may send and what it will get back, so an attribute
// declared but not served is as misleading as one served but not declared.
func TestUserSchemaDescribesTheResource(t *testing.T) {
	attributes := newUserSchema("http://localhost:9999").Attributes
	served := jsonFields(t, fullUser())

	t.Run("declares every attribute a User serves", func(t *testing.T) {
		expected := make([]string, 0, len(served))
		for _, field := range served {
			if !slices.Contains(commonAttributes, field) {
				expected = append(expected, field)
			}
		}

		assert.Equal(t, expected, attributeNames(attributes))
	})

	t.Run("declares the sub-attributes of name", func(t *testing.T) {
		assert.Equal(t,
			jsonFields(t, fullUser().Name),
			attributeNames(subAttributesOf(t, attributes, "name")))
	})

	t.Run("declares the sub-attributes of emails", func(t *testing.T) {
		assert.Equal(t,
			jsonFields(t, fullUser().Emails[0]),
			attributeNames(subAttributesOf(t, attributes, "emails")))
	})

	t.Run("marks emails multi-valued and name not", func(t *testing.T) {
		for _, attribute := range attributes {
			if attribute.Name == "emails" {
				assert.True(t, attribute.MultiValued)
			}
			if attribute.Name == "name" {
				assert.False(t, attribute.MultiValued)
			}
		}
	})
}
