package scim

import (
	"slices"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api/scim/core"
	"github.com/supabase/auth/internal/api/scim/protocol"
)

func TestUserRepository(t *testing.T) {
	db := newTestDB(t)
	repo := newTestRepo(db)
	tenant := newTenant(t, db)
	ctx := ctxFor(tenant)

	t.Run("List", func(t *testing.T) {
		listRepo, listCtx := seedPostgres(t, seedUsers())
		count := len(seedUserNames)

		page := func(t *testing.T, query *protocol.SearchRequest) ([]*core.User, int) {
			t.Helper()

			users, total, err := listRepo.List(listCtx, query)
			require.NoError(t, err)
			return users, total
		}

		// Every page size must walk the whole collection exactly once: no row
		// skipped at a boundary, none served twice.
		t.Run("paginates over the whole collection without gaps or duplicates", func(t *testing.T) {
			whole, total := page(t, &protocol.SearchRequest{StartIndex: 1, Count: count})
			require.Equal(t, count, total)
			require.Len(t, whole, count)

			expected := idsOf(whole)

			for size := 1; size <= count+1; size++ {
				var walked []string
				for start := 1; start <= count; start += size {
					users, _ := page(t, &protocol.SearchRequest{StartIndex: start, Count: size})
					walked = append(walked, idsOf(users)...)
				}

				assert.Equal(t, expected, walked, "page size %d", size)
				assert.Len(t, slices.Compact(slices.Sorted(slices.Values(walked))), count)
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

		t.Run("refuses any filter", func(t *testing.T) {
			_, _, err := listRepo.List(listCtx, &protocol.SearchRequest{
				StartIndex: 1, Count: count, Filter: `userName eq "alice@example.com"`,
			})

			require.ErrorIs(t, err, protocol.ErrInvalidFilter(""))
		})

		t.Run("never lists across tenants", func(t *testing.T) {
			users, total := page(t, &protocol.SearchRequest{StartIndex: 1, Count: count})
			require.Len(t, users, count)
			require.Equal(t, count, total)

			stranger := ctxFor(newTenant(t, listRepo.db))

			isolated, isolatedTotal, err := listRepo.List(stranger, &protocol.SearchRequest{StartIndex: 1, Count: count})
			require.NoError(t, err)
			assert.Empty(t, isolated)
			assert.Zero(t, isolatedTotal)
		})

		t.Run("omits soft-deleted resources", func(t *testing.T) {
			repo, ctx := seedPostgres(t, seedUsers())

			users, _, err := repo.List(ctx, &protocol.SearchRequest{StartIndex: 1, Count: count})
			require.NoError(t, err)
			require.Len(t, users, count)

			require.NoError(t, repo.db.RawQuery("UPDATE scim_users SET deleted_at = now() WHERE id = ?", users[0].ID).Exec())

			remaining, total, err := repo.List(ctx, &protocol.SearchRequest{StartIndex: 1, Count: count})
			require.NoError(t, err)
			assert.Len(t, remaining, count-1)
			assert.Equal(t, count-1, total)
			assert.NotContains(t, idsOf(remaining), users[0].ID)
		})
	})

	t.Run("Get", func(t *testing.T) {
		t.Run("reads a stored resource back", func(t *testing.T) {
			at := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
			stored := newStoredUser(t, db, tenant, &core.User{
				UserName: "bjensen@example.com",
				Meta:     core.Meta{Created: at, LastModified: at},
			})

			got, err := repo.Get(ctx, stored.ID)
			require.NoError(t, err)

			assert.Equal(t, stored.ID, got.ID)
			assert.Equal(t, "bjensen@example.com", got.UserName)
			assert.Equal(t, at, got.Meta.Created)
			assert.Equal(t, at, got.Meta.LastModified)
		})

		t.Run("names the resource type and its own location", func(t *testing.T) {
			stored := newStoredUser(t, db, tenant, &core.User{UserName: "meta@example.com"})

			got, err := repo.Get(ctx, stored.ID)
			require.NoError(t, err)

			assert.Equal(t, core.ResourceTypeName("User"), got.Meta.ResourceType)
			assert.Equal(t, testExternalURL+BasePath+"/Users/"+stored.ID, got.Meta.Location)
		})

		t.Run("defaults active to true when the document omits it", func(t *testing.T) {
			stored := newStoredUser(t, db, tenant, &core.User{UserName: "noactive@example.com"})

			got, err := repo.Get(ctx, stored.ID)
			require.NoError(t, err)

			require.NotNil(t, got.Active)
			assert.True(t, *got.Active)
		})

		t.Run("carries the User schema even when the document omits it", func(t *testing.T) {
			stored := newStoredUser(t, db, tenant, &core.User{UserName: "noschema@example.com"})

			got, err := repo.Get(ctx, stored.ID)
			require.NoError(t, err)

			assert.Equal(t, []core.SchemaURI{core.SchemaUser}, got.Schemas)
		})

		t.Run("an unknown id is ErrNotFound", func(t *testing.T) {
			_, err := repo.Get(ctx, uuid.Must(uuid.NewV4()).String())

			require.ErrorIs(t, err, ErrNotFound)
		})

		t.Run("a soft-deleted resource is ErrNotFound", func(t *testing.T) {
			stored := newStoredUser(t, db, tenant, &core.User{UserName: "gone@example.com"})
			require.NoError(t, db.RawQuery("UPDATE scim_users SET deleted_at = now() WHERE id = ?", stored.ID).Exec())

			_, err := repo.Get(ctx, stored.ID)

			require.ErrorIs(t, err, ErrNotFound)
		})

		// The bearer token resolves the tenant, so it is the isolation boundary:
		// one provider's token must never read another provider's user.
		t.Run("never reads across tenants", func(t *testing.T) {
			other := newTenant(t, db)
			stored := newStoredUser(t, db, other, &core.User{UserName: "theirs@example.com"})

			_, err := repo.Get(ctx, stored.ID)
			require.ErrorIs(t, err, ErrNotFound)

			got, err := repo.Get(ctxFor(other), stored.ID)
			require.NoError(t, err)
			assert.Equal(t, stored.ID, got.ID)
		})
	})
}

// No two are equal once lowercased, because a store may hold userName to being
// unique without regard to case.
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
