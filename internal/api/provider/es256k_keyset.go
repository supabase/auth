package provider

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/oauth2"
)

const es256kAlgorithm = "ES256K"

type oidcDiscoveryClaims struct {
	Issuer                           string   `json:"issuer"`
	JWKSURI                          string   `json:"jwks_uri"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
}

type jwtHeader struct {
	Algorithm string   `json:"alg"`
	KeyID     string   `json:"kid"`
	Critical  []string `json:"crit"`
}

type es256kJWKSet struct {
	Keys []es256kJWK `json:"keys"`
}

type es256kJWK struct {
	KeyType   string `json:"kty"`
	Curve     string `json:"crv"`
	KeyID     string `json:"kid"`
	Algorithm string `json:"alg"`
	Use       string `json:"use"`
	X         string `json:"x"`
	Y         string `json:"y"`
}

type es256kRemoteKeySet struct {
	jwksURL string

	mu         sync.RWMutex
	cachedKeys []es256kJWK
}

var es256kKeySets sync.Map

const es256kKeySetCacheTTL = time.Hour

type cachedES256KKeySet struct {
	keySet    *es256kRemoteKeySet
	createdAt time.Time
}

func getES256KRemoteKeySet(jwksURL string) *es256kRemoteKeySet {
	now := time.Now()
	if value, ok := es256kKeySets.Load(jwksURL); ok {
		cached := value.(cachedES256KKeySet)
		if now.Sub(cached.createdAt) < es256kKeySetCacheTTL {
			return cached.keySet
		}
	}

	cached := cachedES256KKeySet{
		keySet:    newES256KRemoteKeySet(jwksURL),
		createdAt: now,
	}
	es256kKeySets.Store(jwksURL, cached)
	return cached.keySet
}

func newES256KRemoteKeySet(jwksURL string) *es256kRemoteKeySet {
	return &es256kRemoteKeySet{jwksURL: jwksURL}
}

func (r *es256kRemoteKeySet) VerifySignature(ctx context.Context, token string) ([]byte, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("oidc: malformed jwt, expected 3 parts got %d", len(parts))
	}

	header, err := parseJWTHeader(token)
	if err != nil {
		return nil, err
	}
	if header.Algorithm != es256kAlgorithm {
		return nil, fmt.Errorf("oidc: unsupported jwt algorithm %q for ES256K key set", header.Algorithm)
	}
	if len(header.Critical) > 0 {
		return nil, errors.New("oidc: unsupported critical jwt headers")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("oidc: malformed jwt payload: %w", err)
	}

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("oidc: malformed jwt signature: %w", err)
	}
	if len(signature) != 64 {
		return nil, fmt.Errorf("oidc: malformed ES256K signature length %d", len(signature))
	}

	if r.verifyWithKeys(r.keysFromCache(), header, parts[0]+"."+parts[1], signature) {
		return payload, nil
	}

	keys, err := r.keysFromRemote(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching keys %v", err)
	}
	if r.verifyWithKeys(keys, header, parts[0]+"."+parts[1], signature) {
		return payload, nil
	}

	return nil, errors.New("failed to verify id token signature")
}

func parseJWTHeader(token string) (*jwtHeader, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("oidc: malformed jwt, expected 3 parts got %d", len(parts))
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("oidc: malformed jwt header: %w", err)
	}

	var header jwtHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("oidc: malformed jwt header: %w", err)
	}

	return &header, nil
}

func verifySHA256AccessTokenHash(expected, accessToken string) error {
	digest := sha256.Sum256([]byte(accessToken))
	actual := base64.RawURLEncoding.EncodeToString(digest[:len(digest)/2])
	if actual != expected {
		return errors.New("oidc: access token hash does not match value in ID token")
	}
	return nil
}

func supportsES256K(claims oidcDiscoveryClaims, config *oidc.Config) bool {
	if len(config.SupportedSigningAlgs) > 0 {
		return containsSigningAlg(config.SupportedSigningAlgs, es256kAlgorithm)
	}
	return containsSigningAlg(claims.IDTokenSigningAlgValuesSupported, es256kAlgorithm)
}

func containsSigningAlg(algs []string, alg string) bool {
	for _, candidate := range algs {
		if candidate == alg {
			return true
		}
	}
	return false
}

func (r *es256kRemoteKeySet) keysFromCache() []es256kJWK {
	r.mu.RLock()
	defer r.mu.RUnlock()

	keys := make([]es256kJWK, len(r.cachedKeys))
	copy(keys, r.cachedKeys)
	return keys
}

func (r *es256kRemoteKeySet) keysFromRemote(ctx context.Context) ([]es256kJWK, error) {
	req, err := http.NewRequest(http.MethodGet, r.jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("oidc: can't create request: %w", err)
	}

	client := http.DefaultClient
	if c, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok && c != nil {
		client = c
	}

	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("oidc: get keys failed %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc: get keys failed: %s %s", resp.Status, body)
	}

	var keySet es256kJWKSet
	if err := json.Unmarshal(body, &keySet); err != nil {
		return nil, fmt.Errorf("oidc: failed to decode keys: %w %s", err, body)
	}

	r.mu.Lock()
	r.cachedKeys = keySet.Keys
	r.mu.Unlock()

	return keySet.Keys, nil
}

func (r *es256kRemoteKeySet) verifyWithKeys(keys []es256kJWK, header *jwtHeader, signingInput string, signature []byte) bool {
	for _, key := range keys {
		if !key.matches(header.KeyID) {
			continue
		}

		publicKey, err := key.publicKey()
		if err != nil {
			continue
		}

		digest := sha256.Sum256([]byte(signingInput))
		r := new(big.Int).SetBytes(signature[:32])
		s := new(big.Int).SetBytes(signature[32:])
		if ecdsa.Verify(publicKey, digest[:], r, s) {
			return true
		}
	}

	return false
}

func (k es256kJWK) matches(keyID string) bool {
	if keyID != "" && k.KeyID != keyID {
		return false
	}
	if k.KeyType != "EC" || k.Curve != "secp256k1" {
		return false
	}
	if k.Algorithm != "" && k.Algorithm != es256kAlgorithm {
		return false
	}
	if k.Use != "" && k.Use != "sig" {
		return false
	}
	return true
}

func (k es256kJWK) publicKey() (*ecdsa.PublicKey, error) {
	xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, fmt.Errorf("oidc: malformed ES256K key x coordinate: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, fmt.Errorf("oidc: malformed ES256K key y coordinate: %w", err)
	}
	if len(xBytes) != 32 || len(yBytes) != 32 {
		return nil, fmt.Errorf("oidc: malformed ES256K key coordinate lengths %d/%d", len(xBytes), len(yBytes))
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	curve := secp256k1.S256()
	if !curve.IsOnCurve(x, y) {
		return nil, errors.New("oidc: ES256K key is not on secp256k1 curve")
	}

	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}
