package api

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
)

func TestJwks(t *testing.T) {
	// generate RSA key pair for testing
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsaJwkPrivate, err := jwk.FromRaw(rsaPrivateKey)
	require.NoError(t, err)
	rsaJwkPublic, err := rsaJwkPrivate.PublicKey()
	require.NoError(t, err)
	kid := rsaJwkPublic.KeyID()

	cases := []struct {
		desc        string
		config      conf.JWTConfiguration
		expectedLen int
	}{
		{
			desc: "hmac key should not be returned",
			config: conf.JWTConfiguration{
				Aud:    "authenticated",
				Secret: "test-secret",
			},
			expectedLen: 0,
		},
		{
			desc: "rsa public key returned",
			config: conf.JWTConfiguration{
				Aud:    "authenticated",
				Secret: "test-secret",
				Keys: conf.JwtKeysDecoder{
					kid: conf.JwkInfo{
						PublicKey:  rsaJwkPublic,
						PrivateKey: rsaJwkPrivate,
					},
				},
			},
			expectedLen: 1,
		},
	}

	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			mockAPI, _, err := setupAPIForTest()
			require.NoError(t, err)
			mockAPI.config.JWT = c.config

			req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
			w := httptest.NewRecorder()
			mockAPI.handler.ServeHTTP(w, req)
			require.Equal(t, http.StatusOK, w.Code)

			var data map[string]interface{}
			require.NoError(t, json.NewDecoder(w.Body).Decode(&data))
			require.Len(t, data["keys"], c.expectedLen)

			for _, key := range data["keys"].([]interface{}) {
				bytes, err := json.Marshal(key)
				require.NoError(t, err)
				actualKey, err := jwk.ParseKey(bytes)
				require.NoError(t, err)
				require.Equal(t, c.config.Keys[kid].PublicKey, actualKey)
			}
		})
	}
}

func TestWellKnownOpenIDIssuerFallbackToExternalURL(t *testing.T) {
	mockAPI, _, err := setupAPIForTest()
	require.NoError(t, err)

	mockAPI.config.JWT.Issuer = ""
	mockAPI.config.API.ExternalURL = "https://auth.example.com"

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()
	mockAPI.handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var resp OpenIDConfigurationResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))

	require.Equal(t, "https://auth.example.com", resp.Issuer)
	require.True(t, strings.HasPrefix(resp.AuthorizationEndpoint, "https://auth.example.com/"), "authorization_endpoint should be absolute, got %q", resp.AuthorizationEndpoint)
	require.True(t, strings.HasPrefix(resp.TokenEndpoint, "https://auth.example.com/"), "token_endpoint should be absolute, got %q", resp.TokenEndpoint)
	require.True(t, strings.HasPrefix(resp.JWKSURL, "https://auth.example.com/"), "jwks_uri should be absolute, got %q", resp.JWKSURL)
	require.True(t, strings.HasPrefix(resp.UserInfoEndpoint, "https://auth.example.com/"), "userinfo_endpoint should be absolute, got %q", resp.UserInfoEndpoint)
}

func TestWellKnownOpenIDIssuerStripsTrailingSlash(t *testing.T) {
	mockAPI, _, err := setupAPIForTest()
	require.NoError(t, err)

	mockAPI.config.JWT.Issuer = "https://auth.example.com/"
	mockAPI.config.API.ExternalURL = "https://something-else.example.com"

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()
	mockAPI.handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var resp OpenIDConfigurationResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))

	require.Equal(t, "https://auth.example.com", resp.Issuer)
	require.Equal(t, "https://auth.example.com/oauth/authorize", resp.AuthorizationEndpoint)
	require.Equal(t, "https://auth.example.com/oauth/token", resp.TokenEndpoint)
	require.Equal(t, "https://auth.example.com/.well-known/jwks.json", resp.JWKSURL)
	require.Equal(t, "https://auth.example.com/oauth/userinfo", resp.UserInfoEndpoint)
}
