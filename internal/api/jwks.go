package api

import (
	"net/http"

	"github.com/lestrrat-go/jwx/v2/jwa"
	jwk "github.com/lestrrat-go/jwx/v2/jwk"
)

type JwksResponse struct {
	Keys []jwk.Key `json:"keys"`
}

func (a *API) Jwks(w http.ResponseWriter, r *http.Request) error {
	config := a.config
	resp := JwksResponse{
		Keys: []jwk.Key{},
	}

	for _, key := range config.JWT.Keys {
		// don't expose hmac jwk in endpoint
		if key.PublicKey == nil || key.PublicKey.KeyType() == jwa.OctetSeq {
			continue
		}
		resp.Keys = append(resp.Keys, key.PublicKey)
	}

	w.Header().Set("Cache-Control", "public, max-age=600")
	return sendJSON(w, http.StatusOK, resp)
}
