package scim

import (
	"encoding/json"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"

	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase/auth/internal/conf/confload"
	"github.com/supabase/auth/internal/models"
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

func createTenant(t *testing.T, db *storage.Connection) *Tenant {
	t.Helper()

	provider := &Tenant{ID: uuid.Must(uuid.NewV4())}
	require.NoError(t, db.Create(provider))

	t.Cleanup(func() {
		_ = db.Destroy(provider)
	})

	return provider
}

func createUser(t *testing.T, db *storage.Connection, provider *Tenant, user *core.User) {
	t.Helper()

	stored := *user
	stored.ID, stored.Meta = "", core.Meta{}

	document, err := json.Marshal(&stored)
	require.NoError(t, err)

	require.NoError(t, db.RawQuery(
		"INSERT INTO scim_users (id, sso_provider_id, resource, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
		user.ID,
		provider.ID,
		string(document),
		user.Meta.Created,
		user.Meta.LastModified,
	).Exec())
}

func createToken(t *testing.T, db *storage.Connection, provider *Tenant) (*models.SCIMToken, string) {
	t.Helper()

	token, raw := models.NewSCIMToken(provider)
	require.NoError(t, db.Create(token))
	return token, raw
}

func userNamesOf(users []*core.User) []string {
	names := make([]string, 0, len(users))
	for _, user := range users {
		names = append(names, user.UserName)
	}
	return names
}
