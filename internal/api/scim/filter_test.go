package scim

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/supabase-community/scim-go/pkg/core"
)

func filterSchemas() []*core.Schema {
	return []*core.Schema{newUserSchema("http://localhost/scim/v2")}
}

func TestCompileFilterSQL(t *testing.T) {
	cases := []struct {
		name string
		text string
		sql  string
		args []any
	}{
		{
			name: "userName eq is case-insensitive against the lowered column",
			text: `userName eq "bjensen"`,
			sql:  "user_name = lower(?)",
			args: []any{"bjensen"},
		},
		{
			name: "active eq binds a boolean against the promoted column",
			text: `active eq true`,
			sql:  "active = ?",
			args: []any{true},
		},
		{
			name: "ne is null-safe via IS DISTINCT FROM",
			text: `userName ne "bjensen"`,
			sql:  "user_name IS DISTINCT FROM lower(?)",
			args: []any{"bjensen"},
		},
		{
			name: "co lowers both sides",
			text: `userName co "jen"`,
			sql:  "user_name LIKE lower(?)",
			args: []any{"%jen%"},
		},
		{
			name: "sw on a jsonb attribute uses resource text",
			text: `displayName sw "Dr"`,
			sql:  "lower(resource->>'displayName') LIKE lower(?)",
			args: []any{"Dr%"},
		},
		{
			name: "value path matches array elements via EXISTS",
			text: `emails[type eq "work"]`,
			sql:  "EXISTS (SELECT 1 FROM jsonb_array_elements(coalesce(resource->'emails', '[]'::jsonb)) AS e WHERE lower(e->>'type') = lower(?))",
			args: []any{"work"},
		},
		{
			name: "value path composes an inner and",
			text: `emails[type eq "work" and value co "example.com"]`,
			sql:  "EXISTS (SELECT 1 FROM jsonb_array_elements(coalesce(resource->'emails', '[]'::jsonb)) AS e WHERE (lower(e->>'type') = lower(?) AND lower(e->>'value') LIKE lower(?)))",
			args: []any{"work", "%example.com%"},
		},
		{
			name: "composes top-level and",
			text: `userName eq "bob" and active eq true`,
			sql:  "(user_name = lower(?) AND active = ?)",
			args: []any{"bob", true},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fragment, err := filterSQL(filterSchemas(), tc.text)
			require.NoError(t, err)
			assert.Equal(t, tc.sql, fragment.sql)
			assert.Equal(t, tc.args, fragment.args)
		})
	}
}

func TestCompileFilterTypedComparison(t *testing.T) {
	fragment, err := filterSQL(filterSchemas(), `meta.lastModified gt "2020-01-01T00:00:00Z"`)
	require.NoError(t, err)
	assert.Equal(t, "updated_at > ?", fragment.sql)
	require.Len(t, fragment.args, 1)
}

func TestCompileFilterRejections(t *testing.T) {
	cases := []struct {
		name string
		text string
	}{
		{name: "invalid operator for boolean", text: `active gt true`},
		{name: "unknown attribute", text: `nickName eq "x"`},
		{name: "mistyped value", text: `active eq "yes"`},
		{name: "malformed filter", text: `userName zz "x"`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := filterSQL(filterSchemas(), tc.text)
			require.Error(t, err)
		})
	}
}
