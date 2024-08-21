package api

import (
	"net/http"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwa"
	jwk "github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/supabase/auth/internal/conf"
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

func signJwt(config *conf.JWTConfiguration, claims jwt.Claims) (string, error) {
	signingJwk, err := conf.GetSigningJwk(config)
	if err != nil {
		return "", err
	}
	signingMethod := conf.GetSigningAlg(signingJwk)
	token := jwt.NewWithClaims(signingMethod, claims)
	if token.Header == nil {
		token.Header = make(map[string]interface{})
	}

	if _, ok := token.Header["kid"]; !ok {
		if kid := signingJwk.KeyID(); kid != "" {
			token.Header["kid"] = kid
		}
	}
	// this serializes the aud claim to a string
	jwt.MarshalSingleStringAsArray = false
	signingKey, err := conf.GetSigningKey(signingJwk)
	if err != nil {
		return "", err
	}
	signed, err := token.SignedString(signingKey)
	if err != nil {
		return "", err
	}
	return signed, nil
}
