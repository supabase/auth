package scim

import (
	"context"
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

// contractUserNames stress the two ways an implementation can order userName
// wrongly. They vary in case, because userName is not caseExact and so sorts
// without regard to it; and they vary in punctuation, because a database
// collation may rank a hyphen below a letter where Go ranks it by code point --
// on en_US.utf8, "a-z" sorts after "ab" while folded C ordering puts it first.
//
// No two are equal once lowercased, because a store may hold userName to being
// unique without regard to case.
var contractUserNames = []string{
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

// contractUsers are the resources every Store is tested with. The timestamps
// are all the same so that a sort which forgets its tiebreaker has something to
// get wrong, and the ids are random so that the tiebreaker cannot accidentally
// agree with the attribute being sorted on.
func contractUsers() []*core.User {
	at := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

	users := make([]*core.User, 0, len(contractUserNames))
	for _, userName := range contractUserNames {
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

// storeContract is the guarantee Repository makes: StartIndex and Count are a
// window over a total order, so paging at any window size reproduces the whole
// collection exactly once and never twice.
//
// It is written against the interface rather than the Postgres store directly,
// so that a second implementation added later is held to the same window,
// collation, and tiebreaker a client already depends on.
func storeContract(t *testing.T, seed func(t *testing.T, users []*core.User) Repository[*core.User]) {
	count := len(contractUserNames)

	ctx := context.Background()
	repo := seed(t, contractUsers())

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

					assert.Equal(t, expected, walked, "window of %d skipped or repeated a resource", size)
					assert.Len(t, slices.Compact(slices.Sorted(slices.Values(walked))), count,
						"window of %d returned a resource twice", size)
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
}

// seedPostgres is the implementation every contract runs against: it owns a
// tenant so its rows are invisible to other tests, and serves that tenant's
// Users out of Postgres.
func seedPostgres(t *testing.T, users []*core.User) Repository[*core.User] {
	db := newTestDB(t)
	owner := newTenant(t, db)
	for _, user := range users {
		putUser(t, db, owner, user)
	}
	return NewUserStore(db, testExternalURL).For(owner)
}

func TestUserStoreContract(t *testing.T) {
	storeContract(t, seedPostgres)
}

func TestUserStoreWriteContract(t *testing.T) {
	writeContract(t, seedPostgres)
}

// writeContract is the guarantee Repository makes about writes: a resource is
// readable once created, changes replace or patch what it holds, and a deleted
// resource is gone. A handler relies on it holding over whichever store backs
// the server.
func writeContract(t *testing.T, seed func(t *testing.T, users []*core.User) Repository[*core.User]) {
	ctx := context.Background()
	repo := seed(t, nil)

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
}
