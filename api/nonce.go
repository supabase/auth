package api

import (
	"net/http"
	"strings"

	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
)

func (a *API) Nonce(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	config := a.getConfig(ctx)
	instanceID := getInstanceID(ctx)

	if !config.Web3.Enabled {
		return badRequestError("Unsupported web3 provider")
	}

	clientIP := strings.Split(r.RemoteAddr, ":")[0]

	nonce, err := models.NewNonce(instanceID, clientIP)
	if err != nil || nonce == nil {
		return internalServerError("Failed to generate nonce")
	}

	err = a.db.Transaction(func(tx *storage.Connection) error {
		if err := tx.Create(nonce); err != nil {
			return internalServerError("Failed to save nonce")
		}

		return nil
	})

	if err != nil {
		return err
	}

	return sendJSON(w, http.StatusCreated, &nonce)
}
