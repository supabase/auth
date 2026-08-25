package scim

import (
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api/scim/core"
)

func TestUserRepository(t *testing.T) {
	db := newTestDB(t)
	repo := newTestRepo(db)
	tenant := newTenant(t, db)
	ctx := ctxFor(tenant)

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
