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
	events := []scimAuditEvent{}
	for i := range rows {
		removed, err := scimUserRemovalEvents(tx, actor, &rows[i])
		if err != nil {
			return err
		}
		events = append(events, removed...)
	}
	return a.auditSCIMEvents(tx, r, events)
}

func scimUserRemovalEvents(tx *storage.Connection, actor *models.User, row *models.SCIMUser) ([]scimAuditEvent, error) {
	groupIDs, err := models.RemoveSCIMUserFromGroups(tx, row.ID)
	if err != nil {
		return nil, err
	}
	events := make([]scimAuditEvent, 0, len(groupIDs)+1)
	for _, groupID := range groupIDs {
		events = append(events, scimAuditEvent{
			actor:      actor,
			action:     models.SCIMGroupMemberRemovedAction,
			providerID: row.SSOProviderID,
			traits:     scimMemberTraits(groupID, row.ID, row.UserID),
		})
	}
	return append(events, scimAuditEvent{
		actor:      actor,
		action:     models.SCIMUserDeletedAction,
		providerID: row.SSOProviderID,
		traits:     scimUserTraits(row),
	}), nil
}
