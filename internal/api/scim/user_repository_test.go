package scim

import (
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

		t.Run("refuses any filter", func(t *testing.T) {
			_, _, err := repo.List(ctx, &protocol.SearchRequest{StartIndex: 1, Count: count, Filter: `userName eq "alice@example.com"`})
			require.ErrorIs(t, err, protocol.ErrInvalidFilter(""))
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

			require.ErrorIs(t, repo.Delete(ctx, missing), ErrNotFound)
		})
	})
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
