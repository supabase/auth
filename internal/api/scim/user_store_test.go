package scim

import (
	"context"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api/scim/core"
	"github.com/supabase/auth/internal/api/scim/protocol"
)

func TestUserStore(t *testing.T) {
	db := newTestDB(t)
	store := NewUserStore(db, testExternalURL)

	t.Run("reads back the resource it was given", func(t *testing.T) {
		tenant := newTenant(t, db)
		active := true
		stored := newStoredUser(t, db, tenant, &core.User{
			UserName:   "bjensen@example.com",
			ExternalID: "ext-701984",
			Name:       core.Name{GivenName: "Barbara", FamilyName: "Jensen"},
			Emails:     []core.Email{{Value: "bjensen@example.com", Primary: true}},
			Active:     &active,
			Meta: core.Meta{
				Created:      time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC),
				LastModified: time.Date(2026, 8, 21, 12, 30, 0, 0, time.UTC),
			},
		})

		user, err := store.For(tenant).Get(context.Background(), stored.ID)
		require.NoError(t, err)

		assert.Equal(t, "bjensen@example.com", user.UserName)
		assert.Equal(t, "ext-701984", user.ExternalID)
		assert.Equal(t, "Barbara", user.Name.GivenName)
		assert.Equal(t, []core.Email{{Value: "bjensen@example.com", Primary: true}}, user.Emails)
		require.NotNil(t, user.Active)
		assert.True(t, *user.Active)
	})

	t.Run("states the id, schemas and meta itself", func(t *testing.T) {
		tenant := newTenant(t, db)
		created := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
		stored := newStoredUser(t, db, tenant, &core.User{
			UserName: "meta@example.com",
			Meta:     core.Meta{Created: created, LastModified: created},
		})

		user, err := store.For(tenant).Get(context.Background(), stored.ID)
		require.NoError(t, err)

		assert.Equal(t, stored.ID, user.ID)
		assert.Equal(t, []core.SchemaURI{core.SchemaUser}, user.Schemas)
		assert.Equal(t, core.KindUser.Name, user.Meta.ResourceType)
		assert.Equal(t, created, user.Meta.Created)
		assert.Equal(t, testExternalURL+BasePath+"/Users/"+stored.ID, user.Meta.Location)
	})

	t.Run("keeps attributes core.User does not model", func(t *testing.T) {
		tenant := newTenant(t, db)
		id := uuid.Must(uuid.NewV4()).String()

		require.NoError(t, db.RawQuery(
			"INSERT INTO scim_users (id, sso_provider_id, resource) VALUES (?, ?, ?)",
			id, tenant,
			`{"userName":"ext@example.com","title":"Tour Guide",`+
				`"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"department":"Tour Operations"}}`,
		).Exec())

		var resource []byte
		require.NoError(t, db.RawQuery(
			"SELECT resource FROM scim_users WHERE id = ?", id,
		).First(&resource))

		assert.Contains(t, string(resource), "Tour Operations")
		assert.Contains(t, string(resource), "Tour Guide")
	})

	t.Run("does not read another tenant's resource", func(t *testing.T) {
		mine, theirs := newTenant(t, db), newTenant(t, db)
		stored := newStoredUser(t, db, theirs, &core.User{UserName: "theirs@example.com"})

		_, err := store.For(mine).Get(context.Background(), stored.ID)
		require.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("does not read a soft deleted resource", func(t *testing.T) {
		tenant := newTenant(t, db)
		stored := newStoredUser(t, db, tenant, &core.User{UserName: "gone@example.com"})

		require.NoError(t, db.RawQuery(
			"UPDATE scim_users SET deleted_at = now() WHERE id = ?", stored.ID,
		).Exec())

		_, err := store.For(tenant).Get(context.Background(), stored.ID)
		require.ErrorIs(t, err, ErrNotFound)

		_, total, err := store.For(tenant).List(context.Background(), &protocol.SearchRequest{StartIndex: 1, Count: 10})
		require.NoError(t, err)
		assert.Equal(t, 0, total, "a soft deleted resource is not counted")
	})

	t.Run("reports no resource of an unknown id", func(t *testing.T) {
		tenant := newTenant(t, db)

		_, err := store.For(tenant).Get(context.Background(), uuid.Must(uuid.NewV4()).String())
		require.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("refuses to sort by an attribute it cannot order", func(t *testing.T) {
		tenant := newTenant(t, db)

		_, _, err := store.For(tenant).List(context.Background(), &protocol.SearchRequest{
			StartIndex: 1, Count: 10, SortBy: "nickName",
		})

		require.ErrorIs(t, err, protocol.ErrInvalidValue(""))
		assert.Contains(t, err.Error(), "nickName")
	})

	t.Run("counts a tenant's resources without regard to another's", func(t *testing.T) {
		mine, theirs := newTenant(t, db), newTenant(t, db)
		newStoredUser(t, db, mine, &core.User{UserName: "mine@example.com"})
		newStoredUser(t, db, theirs, &core.User{UserName: "theirs@example.com"})
		newStoredUser(t, db, theirs, &core.User{UserName: "theirs2@example.com"})

		users, total, err := store.For(mine).List(context.Background(), &protocol.SearchRequest{StartIndex: 1, Count: 10})
		require.NoError(t, err)

		assert.Equal(t, 1, total)
		require.Len(t, users, 1)
		assert.Equal(t, "mine@example.com", users[0].UserName)
	})
}

// TestUserStoreRejectsADuplicateUserName pins the constraint the write path in
// M4 will rely on to answer 409 uniqueness.
func TestUserStoreCreateRejectsADuplicateUserName(t *testing.T) {
	repo := seedPostgres(t, nil)
	ctx := context.Background()

	_, err := repo.Create(ctx, &core.User{UserName: "BJensen@example.com"})
	require.NoError(t, err)

	_, err = repo.Create(ctx, &core.User{UserName: "bjensen@example.com"})
	require.ErrorIs(t, err, protocol.ErrUniqueness(""),
		"userName is unique without regard to case, and a violation is a 409")
}

// TestUserStoreListRejectsANonUUIDIdFilter pins the fix for a filter on id: the
// value is held to a UUID before a query runs, so a non-UUID is a 400 rejected
// in Go rather than a 500 from casting text to the uuid column.
func TestUserStoreListRejectsANonUUIDIdFilter(t *testing.T) {
	repo := seedPostgres(t, nil)

	_, _, err := repo.List(context.Background(), &protocol.SearchRequest{
		StartIndex: 1, Count: 10, Filter: `id eq "not-a-uuid"`,
	})
	require.ErrorIs(t, err, protocol.ErrInvalidFilter(""),
		"a non-uuid id is a 400 rejected before SQL, not a 500 from the uuid column")
}

// TestUserStorePatchRejectsRemovingUserName pins the fix for a patch that empties
// the required userName: it is a 400 caught before the write rather than a 500
// from the not-null generated column.
func TestUserStorePatchRejectsRemovingUserName(t *testing.T) {
	repo := seedPostgres(t, nil)
	ctx := context.Background()

	created, err := repo.Create(ctx, &core.User{UserName: "bjensen@example.com"})
	require.NoError(t, err)

	_, err = repo.Patch(ctx, created.ID, patchOf(t, `{"Operations":[{"op":"remove","path":"userName"}]}`))
	require.ErrorIs(t, err, protocol.ErrInvalidValue(""),
		"emptying the required userName is a 400, not a 500 from the not-null column")
}

func TestUserStoreRejectsADuplicateUserName(t *testing.T) {
	db := newTestDB(t)
	tenant := newTenant(t, db)

	newStoredUser(t, db, tenant, &core.User{UserName: "BJensen@example.com"})

	document := `{"userName":"bjensen@example.com"}`
	err := db.RawQuery(
		"INSERT INTO scim_users (id, sso_provider_id, resource) VALUES (?, ?, ?)",
		uuid.Must(uuid.NewV4()).String(), tenant, document,
	).Exec()

	require.Error(t, err, "userName is not caseExact, so it is unique without regard to case")
	assert.Contains(t, err.Error(), "scim_users_user_name_key")
}
