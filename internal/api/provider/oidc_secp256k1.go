package provider

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"reflect"
	"strings"
	"time"
	"unsafe"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/golang-jwt/jwt/v5"
)

// jwksResp represents the structure of the JWKS JSON
type jwksResp struct {
	Keys []struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		Kid string `json:"kid"`
		X   string `json:"x"`
		Y   string `json:"y"`
	} `json:"keys"`
}

// openIDConfig represents the discovery document
type openIDConfig struct {
	JwksURI string `json:"jwks_uri"`
	Issuer  string `json:"issuer"`
}

// verifySecp256k1Fallback attempts to verify an ID token manually by fetching the JWKS,
// looking for a secp256k1 key, and performing ECDSA verification.
func verifySecp256k1Fallback(ctx context.Context, provider *oidc.Provider, idToken string) (*oidc.IDToken, *UserProvidedData, error) {
	// Parse the unverified JWT
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, nil, errors.New("invalid jwt format")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, err
	}
	var header struct {
		Kid string `json:"kid"`
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, nil, err
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, err
	}
	var claims struct {
		Iss string   `json:"iss"`
		Sub string   `json:"sub"`
		Aud any      `json:"aud"`
		Exp int64    `json:"exp"`
		Iat int64    `json:"iat"`
		Nonce string `json:"nonce"`
		AtHash string `json:"at_hash"`
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, nil, err
	}

	// 1. Fetch OpenID config to get JWKS URI
	req, err := http.NewRequestWithContext(ctx, "GET", claims.Iss+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("failed to fetch openid config: status %d", resp.StatusCode)
	}

	var config openIDConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, nil, err
	}

	// 2. Fetch JWKS
	jwksReq, err := http.NewRequestWithContext(ctx, "GET", config.JwksURI, nil)
	if err != nil {
		return nil, nil, err
	}
	jwksRespHTTP, err := http.DefaultClient.Do(jwksReq)
	if err != nil {
		return nil, nil, err
	}
	defer jwksRespHTTP.Body.Close()

	if jwksRespHTTP.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("failed to fetch jwks: status %d", jwksRespHTTP.StatusCode)
	}

	var keySet jwksResp
	if err := json.NewDecoder(jwksRespHTTP.Body).Decode(&keySet); err != nil {
		return nil, nil, err
	}

	// 3. Find the key matching kid and crv=secp256k1
	var pubKey *ecdsa.PublicKey
	for _, key := range keySet.Keys {
		if key.Kid == header.Kid && key.Kty == "EC" && key.Crv == "secp256k1" {
			xb, err := base64.RawURLEncoding.DecodeString(key.X)
			if err != nil {
				continue
			}
			yb, err := base64.RawURLEncoding.DecodeString(key.Y)
			if err != nil {
				continue
			}
			pubKey = &ecdsa.PublicKey{
				Curve: secp256k1.S256(),
				X:     new(big.Int).SetBytes(xb),
				Y:     new(big.Int).SetBytes(yb),
			}
			break
		}
	}

	if pubKey == nil {
		return nil, nil, errors.New("secp256k1 public key not found in jwks")
	}

	// 4. Verify the signature
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, nil, err
	}
	if len(sig) != 64 {
		return nil, nil, errors.New("invalid signature length for secp256k1")
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])

	hasher := sha256.New()
	hasher.Write([]byte(parts[0] + "." + parts[1]))
	hash := hasher.Sum(nil)

	if !ecdsa.Verify(pubKey, hash, r, s) {
		return nil, nil, errors.New("secp256k1 signature validation failed")
	}

	// 5. Expiry validation
	if claims.Exp < time.Now().Unix() {
		return nil, nil, errors.New("token is expired")
	}

	// 6. Construct *oidc.IDToken using reflection/unsafe to set unexported fields
	idTokenObj := &oidc.IDToken{
		Issuer:          claims.Iss,
		Subject:         claims.Sub,
		Expiry:          time.Unix(claims.Exp, 0),
		IssuedAt:        time.Unix(claims.Iat, 0),
		Nonce:           claims.Nonce,
		AccessTokenHash: claims.AtHash,
	}

	switch aud := claims.Aud.(type) {
	case string:
		idTokenObj.Audience = []string{aud}
	case []interface{}:
		for _, a := range aud {
			if astr, ok := a.(string); ok {
				idTokenObj.Audience = append(idTokenObj.Audience, astr)
			}
		}
	}

	// Set unexported "claims" field via unsafe
	v := reflect.ValueOf(idTokenObj).Elem()
	claimsField := v.FieldByName("claims")
	if claimsField.IsValid() && claimsField.CanAddr() {
		ptr := unsafe.Pointer(claimsField.UnsafeAddr())
		*(*[]byte)(ptr) = payloadBytes
	}

	// 7. Extract UserProvidedData using standard map claims parsing
	var mapClaims jwt.MapClaims
	if err := json.Unmarshal(payloadBytes, &mapClaims); err != nil {
		return nil, nil, err
	}
	
	// Create a dummy parse Generic token call to extract claims just like standard tokens
	_, data, err := parseGenericIDToken(idTokenObj)
	if err != nil {
		return nil, nil, err
	}

	return idTokenObj, data, nil
}
