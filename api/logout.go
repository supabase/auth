package api

import (
	"encoding/json"
	"net/http"

	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
)

type LogoutParams struct {
	RefreshToken *string `json:"refresh_token"`
}

func getLogoutRefreshToken(a *API, r *http.Request) (string, error) {
	params := LogoutParams{}
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		return "", badRequestError("Could not decode logout params: %v", err)
	}
	if params.RefreshToken == nil {
		return "", nil
	}
	return *params.RefreshToken, nil
}

// Logout is the endpoint for logging out a user and thereby revoking any refresh tokens
func (a *API) Logout(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	instanceID := getInstanceID(ctx)
	config := getConfig(ctx)
	refreshToken, err := getLogoutRefreshToken(a, r)
	if err != nil {
		return badRequestError("Could not read logout request parameters").WithInternalError(err)
	}

	a.clearCookieTokens(config, w)

	u, err := getUserFromClaims(ctx, a.db)
	if err != nil {
		return unauthorizedError("Invalid user").WithInternalError(err)
	}

	var traits map[string]interface{} = nil
	if refreshToken != "" {
		traits = map[string]interface{}{
			"refresh_token": refreshToken,
		}
	}

	err = a.db.Transaction(func(tx *storage.Connection) error {
		if terr := models.NewAuditLogEntry(tx, instanceID, u, models.LogoutAction, traits); terr != nil {
			return terr
		}
		return models.Logout(tx, instanceID, u.ID, refreshToken)
	})
	if err != nil {
		return internalServerError("Error logging out user").WithInternalError(err)
	}

	w.WriteHeader(http.StatusNoContent)
	return nil
}
