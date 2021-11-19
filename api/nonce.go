package api

import (
	"crypto/rand"
	"math/big"
	"net/http"
	"time"
)

type Nonce struct {
	Nonce     string    `json:"nonce"`
	ExpiresAt time.Time `json:"expires_at"`
}

func GenerateRandomString(n int) (string, error) {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		ret[i] = letters[num.Int64()]
	}

	return string(ret), nil
}

func (a *API) Nonce(w http.ResponseWriter, r *http.Request) error {
	nonce, err := GenerateRandomString(32)
	if err != nil {
		return internalServerError("Failed to generate nonce")
	}

	return sendJSON(w, http.StatusOK, &Nonce{
		Nonce:     nonce,
		ExpiresAt: time.Now().Add(time.Minute * 2),
	})
}
