package scim

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
)

func TestUserRepository(t *testing.T) {
	user := func(name string) *core.User {
		t.Helper()

		return &core.User{
			Schemas:  []core.SchemaURI{core.SchemaUser},
			UserName: name,
		}
	}

	db := newTestDB(t)
	owner := createTenant(t, db)
	ctx := tenantKey.WithValue(t.Context(), owner)
	repository := NewUserRepository(db, Join(testExternalURL, BasePath))

	t.Run("List", func(t *testing.T) {
		users := seedUsers()
		count := len(users)
		for _, user := range users {
			createUser(t, db, owner, user)
		}

		page := func(t *testing.T, query *protocol.SearchRequest) ([]*core.User, int) {
			t.Helper()

			users, total, err := repository.List(ctx, query)
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
			_, _, err := repository.List(ctx, &protocol.SearchRequest{StartIndex: 1, Count: 10, SortBy: "nickName"})

			require.ErrorIs(t, err, protocol.ErrInvalidValue(""))
			assert.Contains(t, err.Error(), "nickName")
		})

		t.Run("refuses any filter", func(t *testing.T) {
			_, _, err := repository.List(ctx, &protocol.SearchRequest{StartIndex: 1, Count: count, Filter: `userName eq "alice@example.com"`})
			require.ErrorIs(t, err, protocol.ErrInvalidFilter(""))
		})
	})

	t.Run("Get", func(t *testing.T) {
		t.Run("reads the resource back", func(t *testing.T) {
			created, err := repository.Create(ctx, user("bob"))
			require.NoError(t, err)

			got, err := repository.Get(ctx, created.ID)
			require.NoError(t, err)

			assert.Equal(t, created.ID, got.ID)
			assert.Equal(t, "bob", got.UserName)
			require.NotNil(t, got.Active)
			assert.True(t, *got.Active)
			assert.Equal(t, created.Meta.Created, got.Meta.Created)
			assert.Equal(t, created.Meta.LastModified, got.Meta.LastModified)
		})
	})

	t.Run("Create", func(t *testing.T) {
		t.Run("assigns an id and preserves the attributes", func(t *testing.T) {
			created, err := repository.Create(ctx, user("alice"))
			require.NoError(t, err)
			assert.NotEmpty(t, created.ID)
			assert.Equal(t, "alice", created.UserName)
		})
	})

	t.Run("Replace", func(t *testing.T) {
		t.Run("changes attributes and keeps the id", func(t *testing.T) {
			created, err := repository.Create(ctx, user("carol"))
			require.NoError(t, err)

			replaced, err := repository.Replace(ctx, created.ID, user("carol-renamed"))
			require.NoError(t, err)
			assert.Equal(t, created.ID, replaced.ID)
			assert.Equal(t, "carol-renamed", replaced.UserName)

			got, err := repository.Get(ctx, created.ID)
			require.NoError(t, err)
			assert.Equal(t, "carol-renamed", got.UserName)
		})

		t.Run("keeps active when the body omits it", func(t *testing.T) {
			ctx := tenantKey.WithValue(t.Context(), createTenant(t, db))

			created, err := repository.Create(ctx, user("gilfoyle"))
			require.NoError(t, err)
			require.NotNil(t, created.Active)
			require.True(t, *created.Active)

			require.NoError(t, db.RawQuery("UPDATE scim_users SET resource = jsonb_set(resource, '{active}', 'false') WHERE id = ?", created.ID).Exec())

			replaced, err := repository.Replace(ctx, created.ID, user("gilfoyle-renamed"))
			require.NoError(t, err)
			assert.Equal(t, "gilfoyle-renamed", replaced.UserName)
			require.NotNil(t, replaced.Active)
			assert.False(t, *replaced.Active)
		})

		t.Run("replaces active supplied in the body, per RFC 7644 3.5.1", func(t *testing.T) {
			ctx := tenantKey.WithValue(t.Context(), createTenant(t, db))

			created, err := repository.Create(ctx, user("dinesh"))
			require.NoError(t, err)

			require.NoError(t, db.RawQuery("UPDATE scim_users SET resource = jsonb_set(resource, '{active}', 'false') WHERE id = ?", created.ID).Exec())

			active := true
			reactivating := &core.User{Schemas: []core.SchemaURI{core.SchemaUser}, UserName: "dinesh", Active: &active}

			replaced, err := repository.Replace(ctx, created.ID, reactivating)
			require.NoError(t, err)
			require.NotNil(t, replaced.Active)
			assert.True(t, *replaced.Active)
		})

		t.Run("writing an unknown id is ErrNotFound", func(t *testing.T) {
			missing := uuid.Must(uuid.NewV4()).String()

			_, err := repository.Get(ctx, missing)
			require.ErrorIs(t, err, ErrNotFound)

			_, err = repository.Replace(ctx, missing, user("ghost"))
			require.ErrorIs(t, err, ErrNotFound)

			require.ErrorIs(t, repository.Delete(ctx, missing), ErrNotFound)
		})
	})

	t.Run("Delete", func(t *testing.T) {
		t.Run("unlists resource", func(t *testing.T) {
			created, err := repository.Create(ctx, user("eve"))
			require.NoError(t, err)

			require.NoError(t, repository.Delete(ctx, created.ID))

			_, err = repository.Get(ctx, created.ID)
			require.ErrorIs(t, err, ErrNotFound)
		})
	})
}

func seedUsers() []*core.User {
	users := []*core.User{}
	for _, userName := range []string{
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
	} {
		users = append(users, &core.User{
			ID:       uuid.Must(uuid.NewV4()).String(),
			UserName: userName,
			Meta: core.Meta{
				Created:      time.Now().Add(-1 * time.Hour).UTC(),
				LastModified: time.Now().Add(-1 * time.Hour).UTC(),
			},
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
