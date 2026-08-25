package scimtest

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recorder stands in for *testing.T so that a failing assertion can itself be
// asserted on. testing.TB cannot be implemented outside its own package, which
// is why these helpers take the narrower TB.
type recorder struct {
	errors []string
	fatals []string
}

func (r *recorder) Helper() {}

func (r *recorder) Errorf(format string, args ...any) {
	r.errors = append(r.errors, fmt.Sprintf(format, args...))
}

func (r *recorder) Fatalf(format string, args ...any) {
	r.fatals = append(r.fatals, fmt.Sprintf(format, args...))
}

func TestGolden(t *testing.T) {
	t.Run("reads an example of the specification", func(t *testing.T) {
		require.Contains(t, string(Golden(t, RFC7643MinimalUser)), `"userName"`)
	})

	t.Run("fails the test when the example is not there", func(t *testing.T) {
		r := &recorder{}

		Golden(r, "rfc7643/nonexistent.json")

		require.Len(t, r.fatals, 1)
		assert.Contains(t, r.fatals[0], "nonexistent.json")
	})

	t.Run("names every example it carries", func(t *testing.T) {
		assert.Equal(t, []string{
			"rfc7643/8.1_minimal_user.json",
			"rfc7643/8.2_full_user.json",
			"rfc7643/8.3_enterprise_user.json",
			"rfc7643/8.4_group.json",
			"rfc7643/8.5_service_provider_configuration.json",
			"rfc7643/8.6_resource_types.json",
			"rfc7643/8.7.1_resource_schemas.json",
			"rfc7643/8.7.2_service_provider_schemas.json",
		}, Names())
	})

	t.Run("every example it carries is valid JSON", func(t *testing.T) {
		for _, name := range Names() {
			t.Run(name, func(t *testing.T) {
				_, err := decode(Golden(t, name))
				require.NoError(t, err)
			})
		}
	})
}

func TestAssertJSON(t *testing.T) {
	t.Run("accepts a value that matches the example", func(t *testing.T) {
		value, err := decode(Golden(t, RFC7643MinimalUser))
		require.NoError(t, err)

		require.True(t, AssertJSON(t, RFC7643MinimalUser, value))
	})

	t.Run("reports the path of an attribute that differs", func(t *testing.T) {
		r := &recorder{}

		AssertJSON(r, RFC7643MinimalUser, map[string]any{
			"schemas":  []any{"urn:ietf:params:scim:schemas:core:2.0:User"},
			"id":       "wrong",
			"userName": "bjensen@example.com",
			"meta":     map[string]any{},
		})

		require.Len(t, r.errors, 1)
		assert.Contains(t, r.errors[0], "id")
		assert.Contains(t, r.errors[0], "meta.resourceType")
	})
}

func TestDiff(t *testing.T) {
	t.Run("finds no difference between equal values", func(t *testing.T) {
		assert.Empty(t, diff("", map[string]any{"a": []any{1.0, "two"}}, map[string]any{"a": []any{1.0, "two"}}))
	})

	t.Run("names a missing attribute by its path", func(t *testing.T) {
		want := map[string]any{"name": map[string]any{"givenName": "Barbara", "familyName": "Jensen"}}
		got := map[string]any{"name": map[string]any{"givenName": "Barbara"}}

		assert.Equal(t, []string{"name.familyName"}, diff("", want, got))
	})

	t.Run("names an attribute the round trip added", func(t *testing.T) {
		assert.Equal(t, []string{"active"}, diff("", map[string]any{}, map[string]any{"active": true}))
	})

	t.Run("indexes into a multi-valued attribute", func(t *testing.T) {
		want := map[string]any{"emails": []any{map[string]any{"value": "a@example.com"}}}
		got := map[string]any{"emails": []any{map[string]any{"value": "b@example.com"}}}

		assert.Equal(t, []string{"emails[0].value"}, diff("", want, got))
	})

	t.Run("reports the whole attribute when the value count differs", func(t *testing.T) {
		want := map[string]any{"emails": []any{map[string]any{}, map[string]any{}}}
		got := map[string]any{"emails": []any{map[string]any{}}}

		assert.Equal(t, []string{"emails"}, diff("", want, got))
	})

	t.Run("reports a value of the wrong kind", func(t *testing.T) {
		assert.Equal(t, []string{"active"}, diff("", map[string]any{"active": map[string]any{}}, map[string]any{"active": true}))
	})

	t.Run("matches attribute names case insensitively, per RFC 7643 Section 2.1", func(t *testing.T) {
		assert.Empty(t, diff("", map[string]any{"userName": "bjensen"}, map[string]any{"username": "bjensen"}))
	})
}

func TestRoundTripDiff(t *testing.T) {
	t.Run("lists what a type drops", func(t *testing.T) {
		type sparse struct {
			Schemas  []string `json:"schemas"`
			UserName string   `json:"userName"`
		}

		assert.Equal(t, []string{"id", "meta"}, RoundTripDiff(t, RFC7643MinimalUser, &sparse{}))
	})

	t.Run("lists what a type adds", func(t *testing.T) {
		type padded struct {
			Schemas  []string `json:"schemas"`
			ID       string   `json:"id"`
			UserName string   `json:"userName"`
			Meta     any      `json:"meta"`
			Active   bool     `json:"active"`
		}

		assert.Equal(t, []string{"active"}, RoundTripDiff(t, RFC7643MinimalUser, &padded{}))
	})

	t.Run("lists nothing for a type that carries every attribute", func(t *testing.T) {
		var whole map[string]any

		assert.Empty(t, RoundTripDiff(t, RFC7643MinimalUser, &whole))
	})

	t.Run("fails the test when the example will not decode into the value", func(t *testing.T) {
		r := &recorder{}
		var wrongShape []string

		RoundTripDiff(r, RFC7643MinimalUser, &wrongShape)

		require.Len(t, r.fatals, 1)
		assert.Contains(t, r.fatals[0], "decoding")
	})
}

func TestHelpersFailLoudly(t *testing.T) {
	t.Run("AssertJSON fails the test when the value will not encode", func(t *testing.T) {
		r := &recorder{}

		AssertJSON(r, RFC7643MinimalUser, func() {})

		require.Len(t, r.fatals, 1)
		assert.Contains(t, r.fatals[0], "encoding")
	})

	t.Run("AssertJSON fails the test when the example is not there", func(t *testing.T) {
		r := &recorder{}

		AssertJSON(r, "rfc7643/nonexistent.json", map[string]any{})

		assert.NotEmpty(t, r.fatals)
	})
}
