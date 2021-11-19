package api

import (
	"net/http"
	"time"

	"github.com/netlify/gotrue/crypto"
)

type Nonce struct {
	Nonce     string    `json:"nonce"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (a *API) Nonce(w http.ResponseWriter, r *http.Request) error {
	return sendJSON(w, http.StatusOK, &Nonce{
		Nonce:     crypto.SecureToken(),
		ExpiresAt: time.Now().Add(time.Minute * 2),
	})
}
