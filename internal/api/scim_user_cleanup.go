package api

import (
	"net/http"

	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

func (a *API) deleteSCIMUsers(tx *storage.Connection, r *http.Request, actor *models.User, userID uuid.UUID) error {
	rows, err := models.SoftDeleteSCIMUsersByUserID(tx, userID)
	if err != nil {
		return err
	}
	for i := range rows {
		event, err := scimUserRemovalEvent(tx, actor, &rows[i])
		if err != nil {
			return err
		}
		if err := a.auditSCIM(tx, r, event); err != nil {
			return err
		}
	}
	return nil
}

func scimUserRemovalEvent(tx *storage.Connection, actor *models.User, row *models.SCIMUser) (scimAuditEvent, error) {
	return scimAuditEvent{
		actor:      actor,
		action:     models.SCIMUserDeletedAction,
		providerID: row.SSOProviderID,
		traits:     scimUserTraits(row),
	}, models.RemoveSCIMUserFromGroups(tx, row.ID)
}
