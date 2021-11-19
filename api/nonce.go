package api

import (
	"net/http"
	"strings"

	"github.com/netlify/gotrue/models"
)

func (a *API) Nonce(w http.ResponseWriter, r *http.Request) error {
	clientIP := strings.Split(r.RemoteAddr, ":")[0]

	ctx := r.Context()
	instanceID := getInstanceID(ctx)
	nonce, err := models.NewNonce(instanceID, clientIP)
	if err != nil {
		return internalServerError("Failed to generate nonce")
	}

	// TODO (HarryET): Store nonce in the database

	return sendJSON(w, http.StatusCreated, &nonce)
}
