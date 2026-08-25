package scim

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api/scim/core"
	"github.com/supabase/auth/internal/api/scim/protocol"
)

func ptr[T any](v T) *T { return &v }

func TestUserRepository(t *testing.T) {
	repo, ctx := seedPostgres(t, seedUsers())

	t.Run("List", func(t *testing.T) {
		count := len(seedUserNames)

		page := func(t *testing.T, query *protocol.SearchRequest) ([]*core.User, int) {
			t.Helper()

			users, total, err := repo.List(ctx, query)
			require.NoError(t, err)
			return users, total
		}

		for _, sortBy := range []string{"", "id", "userName", "meta.created", "meta.lastModified"} {
			for _, order := range []protocol.SortOrder{protocol.SortAscending, protocol.SortDescending} {
				t.Run("sortBy="+sortBy+" sortOrder="+string(order), func(t *testing.T) {
					whole, total := page(t, &protocol.SearchRequest{
						StartIndex: 1, Count: count, SortBy: sortBy, SortOrder: order,
					})
					require.Equal(t, count, total)
					require.Len(t, whole, count)

					expected := idsOf(whole)

					for size := 1; size <= count+1; size++ {
						var walked []string
						for start := 1; start <= count; start += size {
							users, _ := page(t, &protocol.SearchRequest{
								StartIndex: start, Count: size, SortBy: sortBy, SortOrder: order,
							})
							walked = append(walked, idsOf(users)...)
						}

						assert.Equal(t, expected, walked)
						assert.Len(t, slices.Compact(slices.Sorted(slices.Values(walked))), count)
					}
				})
			}
		}

		t.Run("reverses the whole order when asked to descend", func(t *testing.T) {
			// meta.created ties every resource, so only a tiebreaker that reverses
			// with the sort makes these two the reverse of one another.
			for _, sortBy := range []string{"id", "meta.created"} {
				t.Run(sortBy, func(t *testing.T) {
					ascending, _ := page(t, &protocol.SearchRequest{StartIndex: 1, Count: count, SortBy: sortBy})
					descending, _ := page(t, &protocol.SearchRequest{
						StartIndex: 1, Count: count, SortBy: sortBy, SortOrder: protocol.SortDescending,
					})

					slices.Reverse(descending)
					assert.Equal(t, idsOf(ascending), idsOf(descending))
				})
			}
		})

		t.Run("reports the total without a page when no resources are wanted", func(t *testing.T) {
			users, total := page(t, &protocol.SearchRequest{StartIndex: 1, Count: 0})

			assert.Empty(t, users)
			assert.Equal(t, count, total)
		})

		t.Run("reports the total of every match, not of the page", func(t *testing.T) {
			users, total := page(t, &protocol.SearchRequest{StartIndex: 1, Count: 5})

			assert.Len(t, users, 5)
			assert.Equal(t, count, total)
		})

		t.Run("returns nothing beyond the end of the collection", func(t *testing.T) {
			users, total := page(t, &protocol.SearchRequest{StartIndex: count + 50, Count: 10})

			assert.Empty(t, users)
			assert.Equal(t, count, total)
		})

		// Go is the reference: RFC 7644 Section 3.4.2.3 orders a userName without
		// regard to case, and this asserts the store agrees with a lowercased code
		// point comparison rather than with whatever collation it happens to run
		// under. A store ordering by the raw column passes on en_US.utf8 and fails
		// on C, so pinning it here holds any implementation to the same order.
		t.Run("orders userName as a lowercased code point comparison", func(t *testing.T) {
			users, _ := page(t, &protocol.SearchRequest{StartIndex: 1, Count: count, SortBy: "userName"})
			names := userNamesOf(users)

			expected := slices.Clone(names)
			slices.SortFunc(expected, func(a, b string) int {
				return strings.Compare(strings.ToLower(a), strings.ToLower(b))
			})

			require.Len(t, names, count)
			assert.Equal(t, expected, names)
		})

		t.Run("names the sort attribute case insensitively, per RFC 7643 Section 2.1", func(t *testing.T) {
			lower, _ := page(t, &protocol.SearchRequest{StartIndex: 1, Count: count, SortBy: "userName"})
			upper, _ := page(t, &protocol.SearchRequest{StartIndex: 1, Count: count, SortBy: "USERNAME"})

			assert.Equal(t, idsOf(lower), idsOf(upper))
		})

		t.Run("refuses to sort by an attribute it cannot order", func(t *testing.T) {
			_, _, err := repo.List(ctx, &protocol.SearchRequest{StartIndex: 1, Count: 10, SortBy: "nickName"})

			require.ErrorIs(t, err, protocol.ErrInvalidValue(""))
			assert.Contains(t, err.Error(), "nickName")
		})

		// Filtering runs under the contract for the same reason ordering does: the
		// resources a filter selects are part of what a client depends on, so they
		// are pinned here rather than left to the store that happens to serve them.
		t.Run("filters", func(t *testing.T) {
			matched := func(t *testing.T, filter string) []string {
				t.Helper()
				users, total, err := repo.List(ctx, &protocol.SearchRequest{StartIndex: 1, Count: count, Filter: filter})
				require.NoError(t, err)
				require.Equal(t, total, len(users), "the whole match set should fit one page")
				return userNamesOf(users)
			}

			t.Run("userName eq selects one, folding case", func(t *testing.T) {
				assert.ElementsMatch(t, []string{"alice@example.com"}, matched(t, `userName eq "ALICE@example.com"`))
			})

			t.Run("userName co selects every substring match", func(t *testing.T) {
				assert.ElementsMatch(t,
					[]string{"carol1@example.com", "carol-1@example.com"},
					matched(t, `userName co "carol"`))
			})

			t.Run("userName pr selects every resource", func(t *testing.T) {
				assert.Len(t, matched(t, `userName pr`), count)
			})

			t.Run("active eq true selects every resource, an absent active being true", func(t *testing.T) {
				assert.Len(t, matched(t, `active eq true`), count)
			})

			t.Run("active eq false selects none", func(t *testing.T) {
				assert.Empty(t, matched(t, `active eq false`))
			})

			t.Run("meta.created eq selects every resource sharing the instant", func(t *testing.T) {
				assert.Len(t, matched(t, `meta.created eq "2026-08-21T12:00:00Z"`), count)
			})

			t.Run("not negates a match", func(t *testing.T) {
				assert.Len(t, matched(t, `not (userName eq "alice@example.com")`), count-1)
			})

			t.Run("and requires both", func(t *testing.T) {
				assert.ElementsMatch(t,
					[]string{"alice@example.com"},
					matched(t, `userName sw "alice" and userName ew "example.com"`))
			})

			for _, rejected := range []string{
				`emails[type eq "work"]`,
				`nickName eq "x"`,
				`meta.created gt "2026-08-21T12:00:00Z"`,
				`id co "abc"`,
				`id eq "not-a-uuid"`,
			} {
				t.Run("refuses "+rejected, func(t *testing.T) {
					_, _, err := repo.List(ctx, &protocol.SearchRequest{StartIndex: 1, Count: count, Filter: rejected})
					require.ErrorIs(t, err, protocol.ErrInvalidFilter(""))
				})
			}
		})
	})

	t.Run("Create", func(t *testing.T) {
		// repo, ctx := seedPostgres(t, nil)

		user := func(name string) *core.User {
			return &core.User{Schemas: []core.SchemaURI{core.SchemaUser}, UserName: name}
		}

		t.Run("Create assigns an id and preserves the attributes", func(t *testing.T) {
			created, err := repo.Create(ctx, user("alice"))
			require.NoError(t, err)
			assert.NotEmpty(t, created.ID)
			assert.Equal(t, "alice", created.UserName)
		})

		t.Run("Create then Get reads the resource back", func(t *testing.T) {
			created, err := repo.Create(ctx, user("bob"))
			require.NoError(t, err)

			got, err := repo.Get(ctx, created.ID)
			require.NoError(t, err)
			assert.Equal(t, created.ID, got.ID)
			assert.Equal(t, "bob", got.UserName)
		})

		t.Run("Replace changes attributes and keeps the id", func(t *testing.T) {
			created, err := repo.Create(ctx, user("carol"))
			require.NoError(t, err)

			replaced, err := repo.Replace(ctx, created.ID, user("carol-renamed"))
			require.NoError(t, err)
			assert.Equal(t, created.ID, replaced.ID)
			assert.Equal(t, "carol-renamed", replaced.UserName)

			got, err := repo.Get(ctx, created.ID)
			require.NoError(t, err)
			assert.Equal(t, "carol-renamed", got.UserName)
		})

		t.Run("Patch applies its operations", func(t *testing.T) {
			created, err := repo.Create(ctx, user("dave"))
			require.NoError(t, err)

			patch, err := protocol.ParsePatchOp([]byte(`{"Operations":[{"op":"replace","value":{"active":false}}]}`))
			require.NoError(t, err)

			patched, err := repo.Patch(ctx, created.ID, patch)
			require.NoError(t, err)
			require.NotNil(t, patched.Active)
			assert.False(t, *patched.Active)

			got, err := repo.Get(ctx, created.ID)
			require.NoError(t, err)
			require.NotNil(t, got.Active)
			assert.False(t, *got.Active)
		})

		t.Run("Delete makes a resource unreadable", func(t *testing.T) {
			created, err := repo.Create(ctx, user("eve"))
			require.NoError(t, err)

			require.NoError(t, repo.Delete(ctx, created.ID))

			_, err = repo.Get(ctx, created.ID)
			require.ErrorIs(t, err, ErrNotFound)
		})

		t.Run("writing an unknown id is ErrNotFound", func(t *testing.T) {
			missing := uuid.Must(uuid.NewV4()).String()

			_, err := repo.Get(ctx, missing)
			require.ErrorIs(t, err, ErrNotFound)

			_, err = repo.Replace(ctx, missing, user("ghost"))
			require.ErrorIs(t, err, ErrNotFound)

			patch, err := protocol.ParsePatchOp([]byte(`{"Operations":[{"op":"replace","value":{"active":false}}]}`))
			require.NoError(t, err)
			_, err = repo.Patch(ctx, missing, patch)
			require.ErrorIs(t, err, ErrNotFound)

			require.ErrorIs(t, repo.Delete(ctx, missing), ErrNotFound)
		})
	})
}

func TestApplyUserPatch(t *testing.T) {
	base := func() *core.User {
		return &core.User{
			ID:         "11111111-1111-1111-1111-111111111111",
			UserName:   "bjensen",
			ExternalID: "ext-1",
			Active:     ptr(true),
			Meta:       core.Meta{ResourceType: "User"},
		}
	}

	t.Run("Okta deactivate replaces active with no path", func(t *testing.T) {
		got, err := applyUserPatch(base(), patchOf(t, `{"Operations":[{"op":"replace","value":{"active":false}}]}`))
		require.NoError(t, err)
		require.Equal(t, ptr(false), got.Active)
		require.Equal(t, "bjensen", got.UserName, "attributes not named are left untouched")
	})

	t.Run("replace a simple attribute by path", func(t *testing.T) {
		got, err := applyUserPatch(base(), patchOf(t, `{"Operations":[{"op":"replace","path":"userName","value":"bj2"}]}`))
		require.NoError(t, err)
		require.Equal(t, "bj2", got.UserName)
	})

	t.Run("replace a sub-attribute by path", func(t *testing.T) {
		got, err := applyUserPatch(base(), patchOf(t, `{"Operations":[{"op":"replace","path":"name.familyName","value":"Jensen"}]}`))
		require.NoError(t, err)
		require.Equal(t, "Jensen", got.Name.FamilyName)
	})

	t.Run("add sets an attribute", func(t *testing.T) {
		got, err := applyUserPatch(base(), patchOf(t, `{"Operations":[{"op":"add","path":"externalId","value":"ext-2"}]}`))
		require.NoError(t, err)
		require.Equal(t, "ext-2", got.ExternalID)
	})

	t.Run("remove clears an attribute", func(t *testing.T) {
		got, err := applyUserPatch(base(), patchOf(t, `{"Operations":[{"op":"remove","path":"externalId"}]}`))
		require.NoError(t, err)
		require.Empty(t, got.ExternalID)
	})

	t.Run("path names an attribute without regard to case", func(t *testing.T) {
		got, err := applyUserPatch(base(), patchOf(t, `{"Operations":[{"op":"replace","path":"ACTIVE","value":false}]}`))
		require.NoError(t, err)
		require.Equal(t, ptr(false), got.Active)
	})

	t.Run("operations apply in order", func(t *testing.T) {
		got, err := applyUserPatch(base(), patchOf(t, `{"Operations":[
			{"op":"replace","path":"userName","value":"first"},
			{"op":"replace","path":"userName","value":"second"}
		]}`))
		require.NoError(t, err)
		require.Equal(t, "second", got.UserName)
	})

	t.Run("rejects a patch that removes userName", func(t *testing.T) {
		_, err := applyUserPatch(base(), patchOf(t, `{"Operations":[{"op":"remove","path":"userName"}]}`))
		require.ErrorIs(t, err, protocol.ErrInvalidValue(""), "userName is required and must not be removed")
	})

	t.Run("rejects a patch that empties userName", func(t *testing.T) {
		_, err := applyUserPatch(base(), patchOf(t, `{"Operations":[{"op":"replace","path":"userName","value":""}]}`))
		require.ErrorIs(t, err, protocol.ErrInvalidValue(""), "userName must not be emptied")
	})

	t.Run("drops an attribute core.User does not model", func(t *testing.T) {
		got, err := applyUserPatch(base(), patchOf(t, `{"Operations":[{"op":"add","path":"displayName","value":"BJ"}]}`))
		require.NoError(t, err)

		encoded, err := json.Marshal(got)
		require.NoError(t, err)
		require.NotContains(t, string(encoded), "displayName", "an unmodeled attribute is not retained")
	})

	t.Run("id and meta are the server's and survive a patch", func(t *testing.T) {
		original := base()
		got, err := applyUserPatch(original, patchOf(t, `{"Operations":[{"op":"replace","value":{"id":"evil","userName":"x"}}]}`))
		require.NoError(t, err)
		require.Equal(t, original.ID, got.ID)
		require.Equal(t, original.Meta, got.Meta)
	})

	t.Run("does not mutate the resource it was given", func(t *testing.T) {
		original := base()
		_, err := applyUserPatch(original, patchOf(t, `{"Operations":[{"op":"replace","value":{"active":false}}]}`))
		require.NoError(t, err)
		require.Equal(t, ptr(true), original.Active, "the input is left unchanged")
	})
}

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

func patchOf(t *testing.T, body string) *protocol.PatchOp {
	t.Helper()
	patch, err := protocol.ParsePatchOp([]byte(body))
	require.NoError(t, err)
	return patch
}

// No two are equal once lowercased, because a store may hold userName to being unique without regard to case.
var seedUserNames = []string{
	"Zoe@example.com",
	"alice@example.com",
	"a-z@example.com",
	"ab@example.com",
	"BJensen@example.com",
	"bob@example.com",
	"carol1@example.com",
	"carol-1@example.com",
	"Dave@example.com",
	"eve@example.com",
	"Frank@example.com",
	"user-00@example.com",
}

func seedUsers() []*core.User {
	at := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

	users := make([]*core.User, 0, len(seedUserNames))
	for _, userName := range seedUserNames {
		users = append(users, &core.User{
			ID:       uuid.Must(uuid.NewV4()).String(),
			UserName: userName,
			Meta:     core.Meta{Created: at, LastModified: at},
		})
	}
	return users
}

func idsOf(users []*core.User) []string {
	ids := make([]string, 0, len(users))
	for _, user := range users {
		ids = append(ids, user.ID)
	}
	return ids
}
