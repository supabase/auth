package provider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

// Regression test for supabase/auth#2494: the generic OIDC parser must
// preserve URN-namespaced claims like Zitadel's role claims.
func TestParseGenericIDTokenPreservesURNNamespacedClaims(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	const keyID = "test-key-1"

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w,
				`{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"jwks_uri":%q,"id_token_signing_alg_values_supported":["RS256"]}`,
				server.URL, server.URL+"/authorize", server.URL+"/token", server.URL+"/jwks",
			)
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(buildJWKSResponse(&privKey.PublicKey, keyID)))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	zitadelRoleClaim := map[string]any{
		"admin": map[string]string{
			"370187779914661893": "zitadel.host.docker.internal",
		},
	}
	claims := jwt.MapClaims{
		"iss":                               server.URL,
		"sub":                               "user-123",
		"aud":                               "test-client-id",
		"iat":                               time.Now().Unix(),
		"exp":                               time.Now().Add(time.Hour).Unix(),
		"email":                             "testuser@example.com",
		"email_verified":                    true,
		"name":                              "Test User",
		"urn:zitadel:iam:org:project:roles": zitadelRoleClaim,
		"urn:zitadel:iam:org:project:370187906414804997:roles": zitadelRoleClaim,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = keyID
	signed, err := tok.SignedString(privKey)
	require.NoError(t, err)

	ctx := context.Background()
	oidcProvider, err := oidc.NewProvider(ctx, server.URL)
	require.NoError(t, err)

	_, data, err := ParseIDToken(ctx, oidcProvider, &oidc.Config{
		SkipClientIDCheck: true,
	}, signed, ParseIDTokenOptions{
		SkipAccessTokenCheck: true,
	})
	require.NoError(t, err)
	require.NotNil(t, data)
	require.NotNil(t, data.Metadata)

	require.Equal(t, "testuser@example.com", data.Metadata.Email)
	require.True(t, data.Metadata.EmailVerified)
	require.Equal(t, "user-123", data.Metadata.Subject)

	require.NotNil(t, data.Metadata.CustomClaims)
	require.Contains(t, data.Metadata.CustomClaims, "urn:zitadel:iam:org:project:roles")
	require.Contains(t, data.Metadata.CustomClaims, "urn:zitadel:iam:org:project:370187906414804997:roles")

	for _, k := range []string{"iss", "sub", "aud", "iat", "exp", "email", "email_verified", "name"} {
		require.NotContains(t, data.Metadata.CustomClaims, k)
	}
}

func buildJWKSResponse(pub *rsa.PublicKey, keyID string) string {
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	jwks := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"kid": keyID,
				"use": "sig",
				"alg": "RS256",
				"n":   n,
				"e":   e,
			},
		},
	}
	out, _ := json.Marshal(jwks)
	return string(out)
}
