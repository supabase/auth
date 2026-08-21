package scim

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/supabase/auth/internal/api/scim/protocol"
)

func TestCompileUserFilter(t *testing.T) {
	cases := []struct {
		name   string
		filter string
		sql    string
		args   []any
	}{
		{
			name:   "userName equals folds case",
			filter: `userName eq "bjensen"`,
			sql:    "lower(user_name) = lower(?)",
			args:   []any{"bjensen"},
		},
		{
			name:   "userName contains",
			filter: `userName co "jen"`,
			sql:    "lower(user_name) LIKE lower(?)",
			args:   []any{"%jen%"},
		},
		{
			name:   "userName starts with",
			filter: `userName sw "b"`,
			sql:    "lower(user_name) LIKE lower(?)",
			args:   []any{"b%"},
		},
		{
			name:   "userName ends with",
			filter: `userName ew "n"`,
			sql:    "lower(user_name) LIKE lower(?)",
			args:   []any{"%n"},
		},
		{
			name:   "contains escapes LIKE metacharacters",
			filter: `userName co "50%_x"`,
			sql:    "lower(user_name) LIKE lower(?)",
			args:   []any{`%50\%\_x%`},
		},
		{
			name:   "externalId is case exact",
			filter: `externalId eq "AbC"`,
			sql:    "external_id = ?",
			args:   []any{"AbC"},
		},
		{
			name:   "externalId presence",
			filter: `externalId pr`,
			sql:    "external_id IS NOT NULL",
			args:   nil,
		},
		{
			name:   "active equals a boolean",
			filter: `active eq true`,
			sql:    "active = ?",
			args:   []any{true},
		},
		{
			name:   "not equal",
			filter: `userName ne "bjensen"`,
			sql:    "lower(user_name) <> lower(?)",
			args:   []any{"bjensen"},
		},
		{
			name:   "and joins with parentheses",
			filter: `userName eq "a" and externalId eq "b"`,
			sql:    "(lower(user_name) = lower(?) AND external_id = ?)",
			args:   []any{"a", "b"},
		},
		{
			name:   "or joins with parentheses",
			filter: `userName eq "a" or userName eq "b"`,
			sql:    "(lower(user_name) = lower(?) OR lower(user_name) = lower(?))",
			args:   []any{"a", "b"},
		},
		{
			name:   "not negates a group",
			filter: `not (userName eq "a")`,
			sql:    "NOT (lower(user_name) = lower(?))",
			args:   []any{"a"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := protocol.ParseFilter(tc.filter)
			require.NoError(t, err)

			sql, args, err := compileUserFilter(parsed)
			require.NoError(t, err)
			require.Equal(t, tc.sql, sql)
			require.Equal(t, tc.args, args)
		})
	}
}

func TestCompileUserFilterBindsTimestamps(t *testing.T) {
	parsed, err := protocol.ParseFilter(`meta.created eq "2026-08-21T12:00:00Z"`)
	require.NoError(t, err)

	sql, args, err := compileUserFilter(parsed)
	require.NoError(t, err)
	require.Equal(t, "created_at = ?", sql)
	require.Len(t, args, 1)

	at, ok := args[0].(time.Time)
	require.True(t, ok, "timestamp is bound as time.Time, not text")
	require.True(t, at.Equal(time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)))
}

func TestCompileUserFilterRejects(t *testing.T) {
	cases := []struct {
		name   string
		filter string
	}{
		{"value path", `emails[type eq "work"]`},
		{"unknown attribute", `nickName eq "x"`},
		{"attribute we do not promote to a column", `name.familyName eq "x"`},
		{"unsupported ordering operator", `meta.created gt "2026-08-21T12:00:00Z"`},
		{"contains on a boolean", `active co "x"`},
		{"boolean compared to a string", `active eq "x"`},
		{"string attribute compared to a number", `userName eq 5`},
		{"substring on id", `id co "abc"`},
		{"id compared to a non-uuid", `id eq "not-a-uuid"`},
		{"unparseable timestamp", `meta.created eq "not-a-date"`},
		{"unknown schema qualified attribute", `urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department eq "x"`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := protocol.ParseFilter(tc.filter)
			require.NoError(t, err)

			_, _, err = compileUserFilter(parsed)
			require.Error(t, err)
			require.True(t, errors.Is(err, protocol.ErrInvalidFilter("")),
				"want ErrInvalidFilter, got %v", err)
		})
	}
}
