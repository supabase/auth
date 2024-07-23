package api

import (
	"crypto/x509"
	"encoding/base64"
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

	for kid, key := range config.JWT.Keys {
		if key.Type == "hmac" {
			// don't display hmac key in jwks
			continue
		}

		// public keys are stored as base64 encoded DER
		derBytes, err := base64.StdEncoding.DecodeString(key.PublicKey)
		if err != nil {
			return internalServerError("Error decoding public key for kid: %v", kid).WithInternalError(err)
		}

		// public keys are assumed to be stored in spki format
		// x509 only supports the P256 curve for EC and ED25519
		pubKey, err := x509.ParsePKIXPublicKey(derBytes)
		if err != nil {
			return internalServerError("Error parsing public key for kid: %v", kid).WithInternalError(err)
		}
		k, err := jwk.FromRaw(pubKey)
		if err != nil {
			return internalServerError("Error parsing jwk for kid: %v", kid).WithInternalError(err)
		}
		k.Set(jwk.KeyIDKey, kid)

		k.Set(jwk.KeyUsageKey, "enc")
		if key.InUse {
			k.Set(jwk.KeyUsageKey, "sig")
		}
		resp.Keys = append(resp.Keys, k)
	}

	return sendJSON(w, http.StatusOK, resp)
}
