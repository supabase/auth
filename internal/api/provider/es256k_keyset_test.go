package provider

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
)

func TestParseIDTokenES256K(t *testing.T) {
	privateKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)

	accessToken := "telegram-access-token"
	accessTokenHash := sha256.Sum256([]byte(accessToken))

	issuer, jwksURI, oidcServer := newES256KOIDCTestServer(t, privateKey.PubKey().ToECDSA(), "telegram-key")
	defer oidcServer.Close()

	idToken := mustSignES256KJWT(t, privateKey.ToECDSA(), map[string]any{
		"alg": es256kAlgorithm,
		"kid": "telegram-key",
		"typ": "JWT",
	}, map[string]any{
		"iss":            issuer,
		"sub":            "telegram-user",
		"aud":            "telegram-client",
		"email":          "telegram@example.com",
		"email_verified": true,
		"iat":            time.Now().Add(-time.Minute).Unix(),
		"exp":            time.Now().Add(time.Hour).Unix(),
		"at_hash":        base64.RawURLEncoding.EncodeToString(accessTokenHash[:len(accessTokenHash)/2]),
	})

	oidcProvider, err := oidc.NewProvider(context.Background(), issuer)
	require.NoError(t, err)

	var claims oidcDiscoveryClaims
	require.NoError(t, oidcProvider.Claims(&claims))
	require.Equal(t, jwksURI, claims.JWKSURI)

	token, user, err := ParseIDToken(context.Background(), oidcProvider, &oidc.Config{
		ClientID: "telegram-client",
	}, idToken, ParseIDTokenOptions{
		AccessToken: accessToken,
	})
	require.NoError(t, err)
	require.Equal(t, issuer, token.Issuer)
	require.Equal(t, "telegram-user", token.Subject)
	require.Len(t, user.Emails, 1)
	require.Equal(t, "telegram@example.com", user.Emails[0].Email)
	require.True(t, user.Emails[0].Verified)
}

func TestParseIDTokenES256KRequiresAdvertisedAlgorithm(t *testing.T) {
	privateKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)

	issuer, _, oidcServer := newES256KOIDCTestServerWithAlgorithms(t, privateKey.PubKey().ToECDSA(), "telegram-key", nil)
	defer oidcServer.Close()

	idToken := mustSignES256KJWT(t, privateKey.ToECDSA(), map[string]any{
		"alg": es256kAlgorithm,
		"kid": "telegram-key",
	}, map[string]any{
		"iss": issuer,
		"sub": "telegram-user",
		"aud": "telegram-client",
		"iat": time.Now().Add(-time.Minute).Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	oidcProvider, err := oidc.NewProvider(context.Background(), issuer)
	require.NoError(t, err)

	_, _, err = ParseIDToken(context.Background(), oidcProvider, &oidc.Config{
		ClientID: "telegram-client",
	}, idToken, ParseIDTokenOptions{SkipAccessTokenCheck: true})
	require.Error(t, err)
}

func TestParseIDTokenES256KRejectsInvalidAccessTokenHash(t *testing.T) {
	privateKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)

	issuer, _, oidcServer := newES256KOIDCTestServer(t, privateKey.PubKey().ToECDSA(), "telegram-key")
	defer oidcServer.Close()

	idToken := mustSignES256KJWT(t, privateKey.ToECDSA(), map[string]any{
		"alg": es256kAlgorithm,
		"kid": "telegram-key",
	}, map[string]any{
		"iss":     issuer,
		"sub":     "telegram-user",
		"aud":     "telegram-client",
		"iat":     time.Now().Add(-time.Minute).Unix(),
		"exp":     time.Now().Add(time.Hour).Unix(),
		"at_hash": "invalid-hash",
	})

	oidcProvider, err := oidc.NewProvider(context.Background(), issuer)
	require.NoError(t, err)

	_, _, err = ParseIDToken(context.Background(), oidcProvider, &oidc.Config{
		ClientID: "telegram-client",
	}, idToken, ParseIDTokenOptions{AccessToken: "telegram-access-token"})
	require.Error(t, err)
}

func TestES256KRemoteKeySetRejectsBadSignature(t *testing.T) {
	privateKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)

	_, jwksURI, oidcServer := newES256KOIDCTestServer(t, privateKey.PubKey().ToECDSA(), "telegram-key")
	defer oidcServer.Close()

	token := mustSignES256KJWT(t, privateKey.ToECDSA(), map[string]any{
		"alg": es256kAlgorithm,
		"kid": "telegram-key",
	}, map[string]any{"sub": "telegram-user"})

	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	parts[2] = base64.RawURLEncoding.EncodeToString(make([]byte, 64))

	_, err = newES256KRemoteKeySet(jwksURI).VerifySignature(context.Background(), strings.Join(parts, "."))
	require.Error(t, err)
}

func TestES256KRemoteKeySetRejectsUnknownKeyID(t *testing.T) {
	privateKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)

	_, jwksURI, oidcServer := newES256KOIDCTestServer(t, privateKey.PubKey().ToECDSA(), "other-key")
	defer oidcServer.Close()

	token := mustSignES256KJWT(t, privateKey.ToECDSA(), map[string]any{
		"alg": es256kAlgorithm,
		"kid": "telegram-key",
	}, map[string]any{"sub": "telegram-user"})

	_, err = newES256KRemoteKeySet(jwksURI).VerifySignature(context.Background(), token)
	require.Error(t, err)
}

func TestES256KRemoteKeySetRejectsInvalidCurvePoint(t *testing.T) {
	keySet := es256kJWKSet{Keys: []es256kJWK{{
		KeyType:   "EC",
		Curve:     "secp256k1",
		KeyID:     "telegram-key",
		Algorithm: es256kAlgorithm,
		Use:       "sig",
		X:         base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		Y:         base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	}}}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewEncoder(w).Encode(keySet))
	}))
	defer server.Close()

	privateKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	token := mustSignES256KJWT(t, privateKey.ToECDSA(), map[string]any{
		"alg": es256kAlgorithm,
		"kid": "telegram-key",
	}, map[string]any{"sub": "telegram-user"})

	_, err = newES256KRemoteKeySet(server.URL).VerifySignature(context.Background(), token)
	require.Error(t, err)
}

func newES256KOIDCTestServer(t *testing.T, publicKey *ecdsa.PublicKey, keyID string) (string, string, *httptest.Server) {
	return newES256KOIDCTestServerWithAlgorithms(t, publicKey, keyID, []string{es256kAlgorithm})
}

func newES256KOIDCTestServerWithAlgorithms(t *testing.T, publicKey *ecdsa.PublicKey, keyID string, algorithms []string) (string, string, *httptest.Server) {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		issuer := "http://" + r.Host
		jwksURI := issuer + "/jwks"

		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			discovery := map[string]any{
				"issuer":                 issuer,
				"authorization_endpoint": issuer + "/authorize",
				"token_endpoint":         issuer + "/token",
				"jwks_uri":               jwksURI,
			}
			if algorithms != nil {
				discovery["id_token_signing_alg_values_supported"] = algorithms
			}
			require.NoError(t, json.NewEncoder(w).Encode(discovery))
		case "/jwks":
			require.NoError(t, json.NewEncoder(w).Encode(es256kJWKSet{Keys: []es256kJWK{{
				KeyType:   "EC",
				Curve:     "secp256k1",
				KeyID:     keyID,
				Algorithm: es256kAlgorithm,
				Use:       "sig",
				X:         base64.RawURLEncoding.EncodeToString(padBigInt(publicKey.X, 32)),
				Y:         base64.RawURLEncoding.EncodeToString(padBigInt(publicKey.Y, 32)),
			}}}))
		default:
			http.NotFound(w, r)
		}
	}))

	return server.URL, server.URL + "/jwks", server
}

func mustSignES256KJWT(t *testing.T, privateKey *ecdsa.PrivateKey, header, claims map[string]any) string {
	t.Helper()

	headerBytes, err := json.Marshal(header)
	require.NoError(t, err)
	claimsBytes, err := json.Marshal(claims)
	require.NoError(t, err)

	signingInput := base64.RawURLEncoding.EncodeToString(headerBytes) + "." + base64.RawURLEncoding.EncodeToString(claimsBytes)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
	require.NoError(t, err)

	signature := append(padBigInt(r, 32), padBigInt(s, 32)...)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func padBigInt(value *big.Int, size int) []byte {
	bytes := value.Bytes()
	if len(bytes) >= size {
		return bytes
	}
	padded := make([]byte, size)
	copy(padded[size-len(bytes):], bytes)
	return padded
}
