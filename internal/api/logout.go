package api

import (
	"fmt"
	"net/http"

	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

type LogoutBehavior string

const (
	LogoutGlobal LogoutBehavior = "global"
	LogoutLocal  LogoutBehavior = "local"
	LogoutOthers LogoutBehavior = "others"
)

// Logout is the endpoint for logging out a user and thereby revoking any refresh tokens
func (a *API) Logout(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	config := a.config

	scope := LogoutGlobal

	if r.URL.Query() != nil {
		switch r.URL.Query().Get("scope") {
		case "", "global":
			scope = LogoutGlobal

		case "local":
			scope = LogoutLocal

		case "others":
			scope = LogoutOthers

		default:
			return badRequestError(ErrorCodeValidationFailed, fmt.Sprintf("Unsupported logout scope %q", r.URL.Query().Get("scope")))
		}
	}

	s := getSession(ctx)
	u := getUser(ctx)

	err := db.Transaction(func(tx *storage.Connection) error {
		if terr := models.NewAuditLogEntry(r, tx, u, models.LogoutAction, "", nil); terr != nil {
			return terr
		}

		if s == nil {
			return models.LogoutAllRefreshTokens(tx, u.ID)
		}

		switch scope {
		case LogoutLocal:
			return models.LogoutSession(tx, s.ID)

		case LogoutOthers:
			return models.LogoutAllExceptMe(tx, s.ID, u.ID)
		}

		// default mode, log out everywhere
		return models.Logout(tx, u.ID)
	})
	if err != nil {
		return internalServerError("Error logging out user").WithInternalError(err)
	}

	a.clearCookieTokens(config, w)
	w.WriteHeader(http.StatusNoContent)

	return nil
}
