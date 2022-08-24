package api

import (
	"net/http"

	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
)

// Logout is the endpoint for logging out a user and thereby revoking any refresh tokens
func (a *API) Logout(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	config := a.config

	a.clearCookieTokens(config, w)

	s := getSession(ctx)
	u := getUser(ctx)

	err := a.db.Transaction(func(tx *storage.Connection) error {
		if terr := models.NewAuditLogEntry(r, tx, u, models.LogoutAction, "", nil); terr != nil {
			return terr
		}
		if s != nil {
			return models.Logout(tx, u.ID)
		}
		return models.LogoutAllRefreshTokens(tx, u.ID)
	})
	if err != nil {
		return internalServerError("Error logging out user").WithInternalError(err)
	}

	w.WriteHeader(http.StatusNoContent)
	return nil
}
