package scim

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"

	"github.com/supabase/auth/internal/api/scim/core"
	"github.com/supabase/auth/internal/conf/confload"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/storage/test"
)

const scimTestConfig = "../../../hack/test.env"

const testExternalURL = "http://localhost:9999"

func newTestDB(t *testing.T) *storage.Connection {
	t.Helper()

	globalConfig, err := confload.LoadGlobal(scimTestConfig)
	require.NoError(t, err)

	conn, err := test.SetupDBConnection(globalConfig)
	require.NoError(t, err)

	return conn
}

func newTenant(t *testing.T, db *storage.Connection) string {
	t.Helper()

	id := uuid.Must(uuid.NewV4()).String()
	require.NoError(t, db.RawQuery("INSERT INTO sso_providers (id, resource_id, created_at, updated_at) VALUES (?, ?, now(), now())", id, "scim-test-"+id).Exec())

	t.Cleanup(func() {
		_ = db.RawQuery("DELETE FROM sso_providers WHERE id = ?", id).Exec()
	})

	return id
}

func putUser(t *testing.T, db *storage.Connection, tenant string, user *core.User) {
	t.Helper()

	stored := *user
	stored.ID, stored.Meta = "", core.Meta{}

	document, err := json.Marshal(&stored)
	require.NoError(t, err)

	require.NoError(t, db.RawQuery(
		"INSERT INTO scim_users (id, sso_provider_id, resource, created_at, updated_at)"+
			" VALUES (?, ?, ?, ?, ?)",
		user.ID, tenant, string(document), user.Meta.Created, user.Meta.LastModified,
	).Exec())
}

func newStoredUser(t *testing.T, db *storage.Connection, tenant string, user *core.User) *core.User {
	t.Helper()

	if user.ID == "" {
		user.ID = uuid.Must(uuid.NewV4()).String()
	}
	putUser(t, db, tenant, user)
	return user
}

func newTestRepo(db *storage.Connection) *userRepository {
	return &userRepository{db: db, baseURL: core.Join(testExternalURL, BasePath)}
}

func ctxFor(tenant string) context.Context {
	return withTenant(context.Background(), tenant)
}

func seedPostgres(t *testing.T, users []*core.User) (Repository[*core.User], context.Context) {
	db := newTestDB(t)
	owner := newTenant(t, db)
	for _, user := range users {
		putUser(t, db, owner, user)
	}
	return newTestRepo(db), ctxFor(owner)
}

func grantToken(t *testing.T, db *storage.Connection, provider string) string {
	t.Helper()

	token, digest := NewSCIMToken()
	require.NoError(t, db.RawQuery(
		"INSERT INTO scim_tokens (sso_provider_id, token_hash) VALUES (?, ?)",
		provider, digest,
	).Exec())

	return token
}

func userNamesOf(users []*core.User) []string {
	names := make([]string, 0, len(users))
	for _, user := range users {
		names = append(names, user.UserName)
	}
	return names
}
