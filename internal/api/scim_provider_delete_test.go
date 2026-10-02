package api

import (
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api/provider"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
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

func (ts *SCIMTestSuite) TestProviderDeleteBansDeprovisionedUsers() {
	active := ts.linkedUser(ts.create(ts.TokenA, scimUser("active")))

	deactivatedID := ts.create(ts.TokenA, scimUser("deactivated"))
	deactivated := ts.linkedUser(deactivatedID)
	ts.setActive(deactivatedID, false)

	deletedID := ts.create(ts.TokenA, scimUser("deleted"))
	deleted := ts.linkedUser(deletedID)
	w, _ := ts.do(ts.TokenA, http.MethodDelete, "/Users/"+deletedID, "")
	require.Equal(ts.T(), http.StatusNoContent, w.Code)

	recreatedID := ts.create(ts.TokenA, scimUser("recreated"))
	recreated := ts.linkedUser(recreatedID)
	w, _ = ts.do(ts.TokenA, http.MethodDelete, "/Users/"+recreatedID, "")
	require.Equal(ts.T(), http.StatusNoContent, w.Code)
	relinkedID := ts.create(ts.TokenA, scimUser("relinked"))
	require.NoError(ts.T(), ts.API.db.RawQuery("UPDATE scim_users SET user_id = ? WHERE id = ?", recreated.ID, relinkedID).Exec())

	ts.createGroup(ts.TokenA, groupWith("A", "", deactivatedID))

	otherID := ts.create(ts.TokenB, scimUser("other"))
	other := ts.linkedUser(otherID)
	ts.setActiveAs(ts.TokenB, otherID, false)

	ts.deleteProvider(ts.A)

	require.False(ts.T(), ts.reloadUser(active.ID).IsBanned())
	require.True(ts.T(), ts.reloadUser(deleted.ID).IsBanned())
	require.False(ts.T(), ts.reloadUser(recreated.ID).IsBanned())
	require.False(ts.T(), ts.reloadUser(other.ID).IsBanned())
	require.True(ts.T(), ts.reloadUser(deactivated.ID).BannedUntil.After(time.Now().Add(99*365*24*time.Hour)))

	require.Zero(ts.T(), ts.countRows(&models.SCIMUser{}, "sso_provider_id = ?", ts.A.ID))
	require.Zero(ts.T(), ts.countRows(&models.SCIMGroup{}, "sso_provider_id = ?", ts.A.ID))
	require.Zero(ts.T(), ts.countRows(&models.SCIMToken{}, "sso_provider_id = ?", ts.A.ID))
	require.Zero(ts.T(), ts.countRows(&models.SCIMGroupMember{}, "1 = 1"))
	require.Equal(ts.T(), 1, ts.countRows(&models.SCIMUser{}, "sso_provider_id = ?", ts.B.ID))
	w, _ = ts.do(ts.TokenB, http.MethodGet, "/Users", "")
	require.Equal(ts.T(), http.StatusOK, w.Code)
}

func (ts *SCIMTestSuite) TestProviderDeleteKeepsLongerBan() {
	id := ts.create(ts.TokenA, scimUser("banned"))
	user := ts.linkedUser(id)
	ts.setActive(id, false)
	require.NoError(ts.T(), user.Ban(ts.API.db, 200*365*24*time.Hour))
	until := *ts.reloadUser(user.ID).BannedUntil

	ts.deleteProvider(ts.A)

	require.True(ts.T(), until.Equal(*ts.reloadUser(user.ID).BannedUntil))
}

func (ts *SCIMTestSuite) TestProviderDeleteClosesOAuthBypass() {
	id := ts.create(ts.TokenA, oktaUser)
	user := ts.linkedUser(id)
	identity, err := models.NewIdentity(user, "google", map[string]any{"sub": "google-sub", "email": "alice@example.com"})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(identity))
	ts.setActive(id, false)

	ts.deleteProvider(ts.A)

	userData := &provider.UserProvidedData{
		Metadata: &provider.Claims{Subject: "google-sub", Email: "alice@example.com", EmailVerified: true},
		Emails:   []provider.Email{{Email: "alice@example.com", Primary: true, Verified: true}},
	}
	err = ts.API.db.Transaction(func(tx *storage.Connection) error {
		_, found, terr := ts.API.createAccountFromExternalIdentity(tx, httptest.NewRequest(http.MethodGet, "/callback", nil), userData, "google", false)
		if terr != nil {
			return terr
		}
		require.Equal(ts.T(), user.ID, found.ID)
		return ts.issueSession(tx, found)
	})
	ts.requireBanned(err)
	require.Zero(ts.T(), ts.sessions(user))
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
	id := ts.create(ts.TokenA, scimUser("disabled"))
	user := ts.linkedUser(id)
	ts.setActive(id, false)
	_, err := models.DisableSCIM(ts.API.db, ts.A.ID)
	require.NoError(ts.T(), err)

	ts.deleteProvider(ts.A)

	require.Empty(ts.T(), ts.auditActions(models.SCIMDisabledAction))
	require.True(ts.T(), ts.reloadUser(user.ID).IsBanned())
}

func (ts *SCIMTestSuite) TestProviderDeleteStillBansWhileSCIMFlagOff() {
	id := ts.create(ts.TokenA, scimUser("flagoff"))
	user := ts.linkedUser(id)
	ts.setActive(id, false)
	before := len(ts.scimAuditEntries())
	ts.API.config.SSO.SCIM.Enabled = false
	defer func() { ts.API.config.SSO.SCIM.Enabled = true }()

	ts.deleteProvider(ts.A)

	require.True(ts.T(), ts.reloadUser(user.ID).IsBanned())
	require.Len(ts.T(), ts.scimAuditEntries(), before)
	require.Empty(ts.T(), ts.auditActions(models.SCIMDisabledAction))
	require.Zero(ts.T(), ts.countRows(&models.SCIMUser{}, "sso_provider_id = ?", ts.A.ID))
}
