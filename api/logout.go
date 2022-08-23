package api

import (
	"net/http"

	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
)

// Logout is the endpoint for logging out a user and thereby revoking any refresh tokens
func (a *API) Logout(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	instanceID := getInstanceID(ctx)
	config := a.config

	a.clearCookieTokens(config, w)

	s, err := getSessionFromClaims(ctx, a.db)
	if err != nil {
		return unauthorizedError("Invalid session").WithInternalError(err)
	}

	var u *models.User
	if s == nil && err == nil {
		// For backward compatibility sake, some claims won't have the sessionId field in it.
		u, err = getUserFromClaims(ctx, a.db)
	} else {
		u, err = models.FindUserByID(a.db, s.UserID)
	}
	if err != nil {
		return unauthorizedError("Invalid user").WithInternalError(err)
	}

	err = a.db.Transaction(func(tx *storage.Connection) error {
		if terr := models.NewAuditLogEntry(r, tx, instanceID, u, models.LogoutAction, "", nil); terr != nil {
			return terr
		}
		return models.Logout(tx, u.ID)
	})
	if err != nil {
		return internalServerError("Error logging out user").WithInternalError(err)
	}

	w.WriteHeader(http.StatusNoContent)
	return nil
}
