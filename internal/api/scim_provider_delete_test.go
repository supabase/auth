package api

import (
	"net/http"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/models"
)

func scimUser(name string) string {
	return userWith(name+"@example.com", name)
}

func (ts *SCIMTestSuite) deleteProvider(p *models.SSOProvider) {
	w := serveAdmin(ts.T(), ts.API, http.MethodDelete, "/admin/sso/providers/"+p.ID.String(), nil)
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
}

func (ts *SCIMTestSuite) reloadUser(id uuid.UUID) *models.User {
	user, err := models.FindUserByID(ts.API.db, id)
	require.NoError(ts.T(), err)
	return user
}

func (ts *SCIMTestSuite) countRows(model any, where string, args ...any) int {
	count, err := ts.API.db.Q().Where(where, args...).Count(model)
	require.NoError(ts.T(), err)
	return count
}

func (ts *SCIMTestSuite) auditActions(action models.AuditAction) []models.AuditLogEntry {
	return queryAuditEntries(ts.T(), ts.API.db, "payload->>'action' = ?", string(action))
}

func (ts *SCIMTestSuite) TestProviderDeleteCascadesSCIMRows() {
	active := ts.linkedUser(ts.create(ts.TokenA, scimUser("active")))
	deactivatedID := ts.create(ts.TokenA, scimUser("deactivated"))
	deactivated := ts.linkedUser(deactivatedID)
	ts.setActive(deactivatedID, false)
	ts.createGroup(ts.TokenA, groupWith("A", "", deactivatedID))
	ts.create(ts.TokenB, scimUser("other"))

	ts.deleteProvider(ts.A)

	require.False(ts.T(), ts.reloadUser(active.ID).IsBanned())
	require.False(ts.T(), ts.reloadUser(deactivated.ID).IsBanned())
	require.Zero(ts.T(), ts.countRows(&models.SCIMUser{}, "sso_provider_id = ?", ts.A.ID))
	require.Zero(ts.T(), ts.countRows(&models.SCIMGroup{}, "sso_provider_id = ?", ts.A.ID))
	require.Zero(ts.T(), ts.countRows(&models.SCIMToken{}, "sso_provider_id = ?", ts.A.ID))
	require.Zero(ts.T(), ts.countRows(&models.SCIMGroupMember{}, "1 = 1"))
	require.Equal(ts.T(), 1, ts.countRows(&models.SCIMUser{}, "sso_provider_id = ?", ts.B.ID))
	w, _ := ts.do(ts.TokenB, http.MethodGet, "/Users", "")
	require.Equal(ts.T(), http.StatusOK, w.Code)
}

func (ts *SCIMTestSuite) TestProviderDeleteAudit() {
	ts.setActive(ts.create(ts.TokenA, scimUser("audited")), false)
	tokens, err := models.FindActiveSCIMTokensBySSOProvider(ts.API.db, ts.A.ID)
	require.NoError(ts.T(), err)
	require.Len(ts.T(), tokens, 1)

	ts.deleteProvider(ts.A)

	disabled := ts.auditActions(models.SCIMDisabledAction)
	require.Len(ts.T(), disabled, 1)
	traits := disabled[0].Payload["traits"].(map[string]any)
	require.Equal(ts.T(), []any{tokens[0].Prefix}, traits["token_prefixes"])
	require.Equal(ts.T(), ts.A.ID.String(), traits["sso_provider_id"])
}

func (ts *SCIMTestSuite) TestProviderDeleteWritesNoGroupEvents() {
	alice := ts.create(ts.TokenA, scimUser("alice"))
	ts.createGroup(ts.TokenA, groupWith("Engineering", "g-1", alice))
	before := ts.countRows(&models.AuditLogEntry{}, "payload->>'action' LIKE 'scim_group_%'")

	ts.deleteProvider(ts.A)

	require.Equal(ts.T(), before, ts.countRows(&models.AuditLogEntry{}, "payload->>'action' LIKE 'scim_group_%'"))
	require.Zero(ts.T(), ts.countRows(&models.SCIMGroup{}, "sso_provider_id = ?", ts.A.ID))
}

func (ts *SCIMTestSuite) TestProviderDeleteAuditWithExpiredTokens() {
	ts.setActive(ts.create(ts.TokenA, scimUser("expired")), false)
	require.NoError(ts.T(), ts.API.db.RawQuery(
		"UPDATE "+(&models.SCIMToken{}).TableName()+" SET created_at = now() - interval '2 hours', expires_at = now() - interval '1 hour' WHERE sso_provider_id = ?", ts.A.ID,
	).Exec())

	ts.deleteProvider(ts.A)

	disabled := ts.auditActions(models.SCIMDisabledAction)
	require.Len(ts.T(), disabled, 1)
	require.Equal(ts.T(), []any{}, disabled[0].Payload["traits"].(map[string]any)["token_prefixes"])
}

func (ts *SCIMTestSuite) TestProviderDeleteWithoutSCIMEnabled() {
	provider := createSSOProvider(ts.T(), ts.API.db)
	_, _, err := models.CreateSCIMToken(ts.API.db, provider, nil)
	require.NoError(ts.T(), err)

	ts.deleteProvider(provider)

	require.Empty(ts.T(), ts.auditActions(models.SCIMDisabledAction))
}

func (ts *SCIMTestSuite) TestProviderDeleteAfterSCIMDisabled() {
	ts.setActive(ts.create(ts.TokenA, scimUser("disabled")), false)
	_, err := models.DisableSCIM(ts.API.db, ts.A.ID)
	require.NoError(ts.T(), err)

	ts.deleteProvider(ts.A)

	require.Empty(ts.T(), ts.auditActions(models.SCIMDisabledAction))
}

func (ts *SCIMTestSuite) TestProviderDeleteWhileSCIMFlagOff() {
	ts.setActive(ts.create(ts.TokenA, scimUser("flagoff")), false)
	before := len(ts.scimAuditEntries())
	ts.API.config.SSO.SCIM.Enabled = false
	defer func() { ts.API.config.SSO.SCIM.Enabled = true }()

	ts.deleteProvider(ts.A)

	require.Len(ts.T(), ts.scimAuditEntries(), before)
	require.Empty(ts.T(), ts.auditActions(models.SCIMDisabledAction))
	require.Zero(ts.T(), ts.countRows(&models.SCIMUser{}, "sso_provider_id = ?", ts.A.ID))
}
