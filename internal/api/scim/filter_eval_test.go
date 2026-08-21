package scim

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/supabase/auth/internal/api/scim/core"
	"github.com/supabase/auth/internal/api/scim/protocol"
)

func ptr[T any](v T) *T { return &v }

func TestMatchUserFilter(t *testing.T) {
	at := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	user := &core.User{
		ID:         "e2b1c0d4-0000-0000-0000-000000000001",
		UserName:   "bjensen",
		ExternalID: "AbC",
		Active:     nil,
		Meta:       core.Meta{Created: at, LastModified: at},
	}

	cases := []struct {
		name   string
		filter string
		want   bool
	}{
		{"userName equals folds case", `userName eq "BJensen"`, true},
		{"userName equals misses", `userName eq "someone"`, false},
		{"userName contains", `userName co "jen"`, true},
		{"userName starts with", `userName sw "bj"`, true},
		{"userName ends with", `userName ew "sen"`, true},
		{"userName starts with misses", `userName sw "zz"`, false},
		{"externalId is case exact and matches", `externalId eq "AbC"`, true},
		{"externalId is case exact and misses on case", `externalId eq "abc"`, false},
		{"externalId present", `externalId pr`, true},
		{"absent active defaults to true", `active eq true`, true},
		{"absent active is not false", `active eq false`, false},
		{"created equals the stored instant", `meta.created eq "2026-08-21T12:00:00Z"`, true},
		{"created equals a different instant", `meta.created eq "2020-01-01T00:00:00Z"`, false},
		{"not negates", `not (userName eq "bjensen")`, false},
		{"and both true", `userName eq "bjensen" and externalId eq "AbC"`, true},
		{"and one false", `userName eq "bjensen" and externalId eq "nope"`, false},
		{"or one true", `userName eq "nope" or externalId eq "AbC"`, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := protocol.ParseFilter(tc.filter)
			require.NoError(t, err)

			got, err := matchUserFilter(user, parsed)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestMatchUserFilterActiveFalse(t *testing.T) {
	user := &core.User{UserName: "x", Active: ptr(false)}

	parsed, err := protocol.ParseFilter(`active eq false`)
	require.NoError(t, err)

	got, err := matchUserFilter(user, parsed)
	require.NoError(t, err)
	require.True(t, got)
}

func TestMatchUserFilterPresenceOfAbsentAttribute(t *testing.T) {
	user := &core.User{UserName: "x"} // no externalId

	parsed, err := protocol.ParseFilter(`externalId pr`)
	require.NoError(t, err)

	got, err := matchUserFilter(user, parsed)
	require.NoError(t, err)
	require.False(t, got)
}

func TestMatchUserFilterRejects(t *testing.T) {
	user := &core.User{UserName: "x"}

	cases := []struct {
		name   string
		filter string
	}{
		{"value path", `emails[type eq "work"]`},
		{"unknown attribute", `nickName eq "x"`},
		{"unsupported ordering operator", `meta.created gt "2026-08-21T12:00:00Z"`},
		{"contains on a boolean", `active co "x"`},
		{"boolean compared to a string", `active eq "x"`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := protocol.ParseFilter(tc.filter)
			require.NoError(t, err)

			_, err = matchUserFilter(user, parsed)
			require.Error(t, err)
			require.True(t, errors.Is(err, protocol.ErrInvalidFilter("")),
				"want ErrInvalidFilter, got %v", err)
		})
	}
}
