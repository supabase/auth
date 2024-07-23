package api

import (
	"net/http"

	jwk "github.com/lestrrat-go/jwx/v2/jwk"
)

type JwksResponse struct {
	Keys []jwk.Key `json:"keys"`
}

func (a *API) Jwks(w http.ResponseWriter, r *http.Request) error {
	config := a.config

	keys := []jwk.Key{}
	resp := JwksResponse{
		Keys: keys,
	}

	for _, key := range config.JWT.Keys {
		// don't expose hmac jwk in endpoint
		if key.PrivateKey.Algorithm().String() == "HS256" {
			continue
		}
		resp.Keys = append(resp.Keys, key.PublicKey)
	}

	return sendJSON(w, http.StatusOK, resp)
}
