package scim

import (
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"

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

func grantToken(t *testing.T, db *storage.Connection, provider string) string {
	t.Helper()

	token, digest := NewToken()
	require.NoError(t, db.RawQuery(
		"INSERT INTO scim_tokens (sso_provider_id, token_hash) VALUES (?, ?)",
		provider, digest,
	).Exec())

	return token
}
