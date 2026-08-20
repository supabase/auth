package core

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAttribute(t *testing.T) {
	attribute := NewAttribute("userName", TypeString, "A unique identifier for the user.")

	t.Run("describes the attribute it names", func(t *testing.T) {
		assert.Equal(t, "userName", attribute.Name)
		assert.Equal(t, TypeString, attribute.Type)
		assert.Equal(t, "A unique identifier for the user.", attribute.Description)
	})

	t.Run("defaults to a readWrite attribute returned by default", func(t *testing.T) {
		assert.Equal(t, MutabilityReadWrite, attribute.Mutability)
		assert.Equal(t, ReturnedDefault, attribute.Returned)
		assert.Equal(t, UniquenessNone, attribute.Uniqueness)
	})

	t.Run("defaults to an optional, single valued, case insensitive attribute", func(t *testing.T) {
		assert.False(t, attribute.Required)
		assert.False(t, attribute.MultiValued)
		assert.False(t, attribute.CaseExact)
	})

	t.Run("serializes to JSON correctly", func(t *testing.T) {
		body, err := json.Marshal(attribute)

		require.NoError(t, err)
		require.JSONEq(t, `{
			"name": "userName",
			"type": "string",
			"multiValued": false,
			"description": "A unique identifier for the user.",
			"required": false,
			"caseExact": false,
			"mutability": "readWrite",
			"returned": "default",
			"uniqueness": "none"
		}`, string(body))
	})
}

func TestAttribute(t *testing.T) {
	t.Run("marks the attribute the client must send", func(t *testing.T) {
		attribute := NewAttribute("userName", TypeString, "A unique identifier for the user.")

		require.Same(t, attribute, attribute.AsRequired())
		assert.True(t, attribute.Required)
	})

	t.Run("marks the attribute that holds more than one value", func(t *testing.T) {
		attribute := NewAttribute("emails", TypeComplex, "The email addresses for the user.")

		require.Same(t, attribute, attribute.AsMultiValued())
		assert.True(t, attribute.MultiValued)
	})

	t.Run("marks the attribute whose value is compared case sensitively", func(t *testing.T) {
		attribute := NewAttribute("id", TypeString, "A unique identifier for the resource.")

		require.Same(t, attribute, attribute.AsCaseExact())
		assert.True(t, attribute.CaseExact)
	})

	t.Run("states the scope the service provider enforces uniqueness over", func(t *testing.T) {
		attribute := NewAttribute("userName", TypeString, "A unique identifier for the user.")

		require.Same(t, attribute, attribute.UniqueOn(UniquenessServer))

		body, err := json.Marshal(attribute)

		require.NoError(t, err)
		require.Contains(t, string(body), `"uniqueness":"server"`)
	})

	t.Run("suggests the canonical values a client may send", func(t *testing.T) {
		attribute := NewAttribute("type", TypeString, "A label indicating the attribute's function.").
			Suggesting("work", "home", "other")

		body, err := json.Marshal(attribute)

		require.NoError(t, err)
		require.Contains(t, string(body), `"canonicalValues":["work","home","other"]`)
	})

	t.Run("names the resource types a reference may point at", func(t *testing.T) {
		attribute := NewAttribute("$ref", TypeReference, "The URI of the corresponding resource.")

		require.Same(t, attribute, attribute.Referencing(string(KindUser.Name), ReferenceExternal, ReferenceURI))

		body, err := json.Marshal(attribute)

		require.NoError(t, err)
		require.Contains(t, string(body), `"referenceTypes":["User","external","uri"]`)
	})

	t.Run("nests the sub-attributes of a complex attribute", func(t *testing.T) {
		givenName := NewAttribute("givenName", TypeString, "The given name of the user.")
		name := NewAttribute("name", TypeComplex, "The components of the user's name.")

		require.Same(t, name, name.With(givenName))
		require.Equal(t, []*Attribute{givenName}, name.SubAttributes)

		body, err := json.Marshal(name)

		require.NoError(t, err)
		require.JSONEq(t, `{
			"name": "name",
			"type": "complex",
			"multiValued": false,
			"description": "The components of the user's name.",
			"required": false,
			"caseExact": false,
			"mutability": "readWrite",
			"returned": "default",
			"uniqueness": "none",
			"subAttributes": [{
				"name": "givenName",
				"type": "string",
				"multiValued": false,
				"description": "The given name of the user.",
				"required": false,
				"caseExact": false,
				"mutability": "readWrite",
				"returned": "default",
				"uniqueness": "none"
			}]
		}`, string(body))
	})

	t.Run("composes every refinement in a chain", func(t *testing.T) {
		attribute := NewAttribute("emails", TypeComplex, "The email addresses for the user.").
			AsRequired().
			AsMultiValued().
			AsCaseExact().
			UniqueOn(UniquenessGlobal).
			Suggesting("work", "home").
			With(NewAttribute("value", TypeString, "The email address."))

		assert.True(t, attribute.Required)
		assert.True(t, attribute.MultiValued)
		assert.True(t, attribute.CaseExact)
		assert.Equal(t, UniquenessGlobal, attribute.Uniqueness)
		assert.Equal(t, []string{"work", "home"}, attribute.CanonicalValues)
		assert.Len(t, attribute.SubAttributes, 1)

		body, err := json.Marshal(attribute)

		require.NoError(t, err)
		require.Contains(t, string(body), `"uniqueness":"global"`)
	})

	t.Run("serializes an attribute the client can neither write nor read back", func(t *testing.T) {
		attribute := NewAttribute("password", TypeString, "The user's cleartext password.")
		attribute.Mutability = MutabilityWriteOnly
		attribute.Returned = ReturnedNever

		body, err := json.Marshal(attribute)

		require.NoError(t, err)
		require.Contains(t, string(body), `"mutability":"writeOnly"`)
		require.Contains(t, string(body), `"returned":"never"`)
	})
}
