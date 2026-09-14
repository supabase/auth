package scim

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
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

			require.ErrorIs(t, err, scimerrors.ErrInvalidValue(""))
			assert.Contains(t, err.Error(), "nickName")
		})

		t.Run("filters by an exact userName", func(t *testing.T) {
			users, total, err := repository.List(ctx, &protocol.SearchRequest{StartIndex: 1, Count: count, Filter: `userName eq "alice@example.com"`})
			require.NoError(t, err)
			assert.Equal(t, 1, total)
			assert.Equal(t, []string{"alice@example.com"}, userNamesOf(users))
		})

		t.Run("matches a userName case-insensitively against the lowered column", func(t *testing.T) {
			users, total, err := repository.List(ctx, &protocol.SearchRequest{StartIndex: 1, Count: count, Filter: `userName eq "bjensen@example.com"`})
			require.NoError(t, err)
			assert.Equal(t, 1, total)
			assert.Equal(t, []string{"BJensen@example.com"}, userNamesOf(users))
		})

		t.Run("filters case-insensitively with co", func(t *testing.T) {
			users, _, err := repository.List(ctx, &protocol.SearchRequest{StartIndex: 1, Count: count, Filter: `userName co "JENSEN"`})
			require.NoError(t, err)
			assert.Equal(t, []string{"BJensen@example.com"}, userNamesOf(users))
		})

		t.Run("filters with co on the lowered column", func(t *testing.T) {
			users, _, err := repository.List(ctx, &protocol.SearchRequest{StartIndex: 1, Count: count, Filter: `userName co "jen"`})
			require.NoError(t, err)
			assert.Equal(t, []string{"BJensen@example.com"}, userNamesOf(users))
		})

		t.Run("filters with ne, excluding the match", func(t *testing.T) {
			users, total, err := repository.List(ctx, &protocol.SearchRequest{StartIndex: 1, Count: count, Filter: `userName ne "bjensen@example.com"`})
			require.NoError(t, err)
			assert.Equal(t, count-1, total)
			assert.NotContains(t, userNamesOf(users), "BJensen@example.com")
		})

		t.Run("filters active users", func(t *testing.T) {
			users, total, err := repository.List(ctx, &protocol.SearchRequest{StartIndex: 1, Count: count, Filter: `active eq true`})
			require.NoError(t, err)
			assert.Equal(t, count-1, total)
			assert.NotContains(t, userNamesOf(users), seedInactiveUserName)
		})

		t.Run("filters with sw on a jsonb attribute", func(t *testing.T) {
			users, _, err := repository.List(ctx, &protocol.SearchRequest{StartIndex: 1, Count: count, Filter: `displayName sw "Dr"`})
			require.NoError(t, err)
			assert.Equal(t, []string{seedDisplayUserName}, userNamesOf(users))
		})

		t.Run("filters a value path against array elements", func(t *testing.T) {
			users, _, err := repository.List(ctx, &protocol.SearchRequest{StartIndex: 1, Count: count, Filter: `emails[type eq "work"]`})
			require.NoError(t, err)
			assert.Equal(t, []string{seedWorkEmailUserName}, userNamesOf(users))
		})

		t.Run("filters a value path composing an inner and", func(t *testing.T) {
			users, _, err := repository.List(ctx, &protocol.SearchRequest{StartIndex: 1, Count: count, Filter: `emails[type eq "work" and value co "example.com"]`})
			require.NoError(t, err)
			assert.Equal(t, []string{seedWorkEmailUserName}, userNamesOf(users))
		})

		t.Run("composes a top-level and", func(t *testing.T) {
			users, total, err := repository.List(ctx, &protocol.SearchRequest{StartIndex: 1, Count: count, Filter: `userName eq "bob@example.com" and active eq true`})
			require.NoError(t, err)
			assert.Equal(t, 1, total)
			assert.Equal(t, []string{"bob@example.com"}, userNamesOf(users))
		})

		t.Run("escapes LIKE metacharacters in co", func(t *testing.T) {
			users, _, err := repository.List(ctx, &protocol.SearchRequest{StartIndex: 1, Count: count, Filter: `userName co "a_b%c\\d"`})
			require.NoError(t, err)
			assert.Equal(t, []string{seedLikeUserName}, userNamesOf(users))
		})

		t.Run("negates null-safely with not", func(t *testing.T) {
			users, total, err := repository.List(ctx, &protocol.SearchRequest{StartIndex: 1, Count: count, Filter: `not (displayName eq "x")`})
			require.NoError(t, err)
			assert.Equal(t, count-1, total)

			names := userNamesOf(users)
			assert.NotContains(t, names, seedDisplayXUserName)
			assert.Contains(t, names, "alice@example.com")
		})

		t.Run("filters by an exact id", func(t *testing.T) {
			users, total, err := repository.List(ctx, &protocol.SearchRequest{StartIndex: 1, Count: count, Filter: fmt.Sprintf("id eq %q", seedFixedID)})
			require.NoError(t, err)
			assert.Equal(t, 1, total)
			assert.Equal(t, []string{seedWorkEmailUserName}, userNamesOf(users))
		})

		t.Run("filters id as text with co", func(t *testing.T) {
			users, _, err := repository.List(ctx, &protocol.SearchRequest{StartIndex: 1, Count: count, Filter: `id co "aaaaaaaa"`})
			require.NoError(t, err)
			assert.Equal(t, []string{seedWorkEmailUserName}, userNamesOf(users))
		})

		t.Run("compares a typed datetime attribute", func(t *testing.T) {
			users, total, err := repository.List(ctx, &protocol.SearchRequest{StartIndex: 1, Count: count, Filter: `meta.lastModified gt "2020-01-01T00:00:00Z"`})
			require.NoError(t, err)
			assert.Equal(t, count-1, total)
			assert.NotContains(t, userNamesOf(users), seedAncientUserName)
		})

		t.Run("rejects invalid filters", func(t *testing.T) {
			cases := []struct {
				name   string
				filter string
			}{
				{name: "invalid operator for boolean", filter: `active gt true`},
				{name: "unknown attribute", filter: `nickName eq "x"`},
				{name: "mistyped value", filter: `active eq "yes"`},
				{name: "malformed filter", filter: `userName zz "x"`},
				{name: "id eq a non-uuid value", filter: `id eq "not-a-uuid"`},
				{name: "co is not valid for a boolean value-path sub-attribute", filter: `emails[primary co "true"]`},
			}

			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					_, _, err := repository.List(ctx, &protocol.SearchRequest{StartIndex: 1, Count: count, Filter: tc.filter})
					require.Error(t, err)
				})
			}
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

const (
	seedInactiveUserName  = "inactive@example.com"
	seedDisplayUserName   = "strange@example.com"
	seedWorkEmailUserName = "work@example.com"
	seedLikeUserName      = "a_b%c\\d@example.com"
	seedLikeDecoyUserName = "axbzcd@example.com"
	seedDisplayXUserName  = "letterx@example.com"
	seedAncientUserName   = "ancient@example.com"
	seedFixedID           = "aaaaaaaa-0000-0000-0000-000000000001"
)

func seedUsers() []*core.User {
	inactive := false
	base := time.Now().Add(-1 * time.Hour).UTC()
	ancient := time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)

	type seed struct {
		id          string
		userName    string
		displayName string
		active      *bool
		emails      []core.Email
		created     time.Time
	}

	seeds := []seed{
		{userName: "Zoe@example.com"},
		{userName: "alice@example.com"},
		{userName: "a-z@example.com"},
		{userName: "ab@example.com"},
		{userName: "BJensen@example.com"},
		{userName: "bob@example.com"},
		{userName: "carol1@example.com"},
		{userName: "carol-1@example.com"},
		{userName: "Dave@example.com"},
		{userName: "eve@example.com"},
		{userName: "Frank@example.com"},
		{userName: "user-00@example.com"},
		{userName: seedInactiveUserName, active: &inactive},
		{userName: seedDisplayUserName, displayName: "Dr. Strange"},
		{userName: seedWorkEmailUserName, id: seedFixedID, emails: []core.Email{{Type: "work", Value: "member@example.com"}}},
		{userName: seedLikeUserName},
		{userName: seedLikeDecoyUserName},
		{userName: seedDisplayXUserName, displayName: "x"},
		{userName: seedAncientUserName, created: ancient},
	}

	users := make([]*core.User, 0, len(seeds))
	for i, s := range seeds {
		created := s.created
		if created.IsZero() {
			created = base
		}
		id := s.id
		if id == "" {
			id = fmt.Sprintf("00000000-0000-0000-0000-%012d", i+1)
		}
		users = append(users, &core.User{
			ID:          id,
			UserName:    s.userName,
			DisplayName: s.displayName,
			Active:      s.active,
			Emails:      s.emails,
			Meta: core.Meta{
				Created:      created,
				LastModified: created,
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
