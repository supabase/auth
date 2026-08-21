package scim

import (
	"context"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api/scim/core"
	"github.com/supabase/auth/internal/api/scim/protocol"
)

const tenant = "8a2f1c34-0000-0000-0000-000000000000"

// seedUsers fills a store with users that deliberately share a userName
// and a created timestamp, so that a sort which forgets its tiebreaker has
// something to get wrong.
func seedUsers(t *testing.T, count int) *MemoryStore[*core.User] {
	t.Helper()

	repo := NewMemoryUserStore()
	created := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

	for i := range count {
		repo.Put(tenant, &core.User{
			ID:       strconv.Itoa(i),
			UserName: "duplicate",
			Meta:     core.Meta{Created: created},
		})
	}
	return repo
}

func page(t *testing.T, repo *MemoryStore[*core.User], query *protocol.SearchRequest) ([]*core.User, int) {
	t.Helper()

	users, total, err := repo.For(tenant).List(context.Background(), query)
	require.NoError(t, err)
	return users, total
}

func TestMemoryStoreList(t *testing.T) {
	t.Run("reports the total without a page when no resources are wanted", func(t *testing.T) {
		users, total := page(t, seedUsers(t, 7), &protocol.SearchRequest{StartIndex: 1, Count: 0})

		assert.Empty(t, users)
		assert.Equal(t, 7, total)
	})

	t.Run("reports the total of every match, not of the page", func(t *testing.T) {
		users, total := page(t, seedUsers(t, 50), &protocol.SearchRequest{StartIndex: 1, Count: 10})

		assert.Len(t, users, 10)
		assert.Equal(t, 50, total)
	})

	t.Run("returns nothing beyond the end of the collection", func(t *testing.T) {
		users, total := page(t, seedUsers(t, 3), &protocol.SearchRequest{StartIndex: 99, Count: 10})

		assert.Empty(t, users)
		assert.Equal(t, 3, total)
	})

	t.Run("refuses to sort by an attribute it cannot order", func(t *testing.T) {
		_, _, err := seedUsers(t, 3).For(tenant).List(context.Background(), &protocol.SearchRequest{
			StartIndex: 1, Count: 10, SortBy: "nickName",
		})

		require.ErrorIs(t, err, protocol.ErrInvalidValue(""))
		assert.Contains(t, err.Error(), "nickName")
	})

	t.Run("names attributes case insensitively, per RFC 7643 Section 2.1", func(t *testing.T) {
		_, _, err := seedUsers(t, 3).For(tenant).List(context.Background(), &protocol.SearchRequest{
			StartIndex: 1, Count: 10, SortBy: "USERname",
		})

		require.NoError(t, err)
	})

	t.Run("orders a tenant's resources without regard to another tenant's", func(t *testing.T) {
		repo := seedUsers(t, 3)
		repo.Put("other-tenant", &core.User{ID: "999"})

		users, total := page(t, repo, &protocol.SearchRequest{StartIndex: 1, Count: 10})

		assert.Equal(t, 3, total)
		assert.Len(t, users, 3)
	})
}

// TestMemoryStorePagesTotally is the guarantee the Repository interface
// makes: startIndex and count are a window over a total order. Paging at every
// window size must reproduce the whole collection exactly once, because a
// window over a partial order silently skips and repeats rows between pages.
func TestMemoryStorePagesTotally(t *testing.T) {
	const count = 12

	for _, sortBy := range []string{"", "id", "userName", "meta.created", "meta.lastModified"} {
		for _, order := range []protocol.SortOrder{protocol.SortAscending, protocol.SortDescending} {
			t.Run("sortBy="+sortBy+" sortOrder="+string(order), func(t *testing.T) {
				repo := seedUsers(t, count)

				whole, total := page(t, repo, &protocol.SearchRequest{
					StartIndex: 1, Count: count, SortBy: sortBy, SortOrder: order,
				})
				require.Equal(t, count, total)
				require.Len(t, whole, count)

				for size := 1; size <= count+1; size++ {
					var walked []string
					for start := 1; start <= count; start += size {
						users, _ := page(t, repo, &protocol.SearchRequest{
							StartIndex: start, Count: size, SortBy: sortBy, SortOrder: order,
						})
						for _, user := range users {
							walked = append(walked, user.ID)
						}
					}

					expected := make([]string, 0, count)
					for _, user := range whole {
						expected = append(expected, user.ID)
					}

					assert.Equal(t, expected, walked, "window of %d skipped or repeated a resource", size)
					assert.Len(t, slices.Compact(slices.Sorted(slices.Values(walked))), count,
						"window of %d returned a resource twice", size)
				}
			})
		}
	}

	t.Run("reverses the order when asked to descend", func(t *testing.T) {
		repo := seedUsers(t, 5)

		ascending, _ := page(t, repo, &protocol.SearchRequest{StartIndex: 1, Count: 5, SortBy: "id"})
		descending, _ := page(t, repo, &protocol.SearchRequest{
			StartIndex: 1, Count: 5, SortBy: "id", SortOrder: protocol.SortDescending,
		})

		slices.Reverse(descending)
		assert.Equal(t, ascending, descending)
	})
}
