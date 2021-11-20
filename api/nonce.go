package api

import (
	"net/http"
	"strings"

	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
)

func (a *API) Nonce(w http.ResponseWriter, r *http.Request) error {
	clientIP := strings.Split(r.RemoteAddr, ":")[0]

	ctx := r.Context()
	instanceID := getInstanceID(ctx)
	nonce, err := models.NewNonce(instanceID, clientIP)
	if err != nil || nonce == nil {
		return internalServerError("Failed to generate nonce")
	}

	// TODO (HarryET): Store nonce in the database
	err = a.db.Transaction(func(tx *storage.Connection) error {
		if err := tx.Create(nonce); err != nil {
			// TODO (HarryET): Debug why "nonces" RELATIONSHIP isn't found by pop
			println(err.Error())
			return internalServerError("Failed to save nonce")
		}

		return nil
	})

	if err != nil {
		return err
	}

	return sendJSON(w, http.StatusCreated, &nonce)
}
