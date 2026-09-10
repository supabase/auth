package provider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestExchangeAuthorizationCode_RawBasicAuth(t *testing.T) {
	const (
		clientID     = "epic-client"
		clientSecret = "secret+with/special=chars"
		authCode     = "auth-code-123"
	)

	var requestCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)

		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

		user, pass, ok := r.BasicAuth()
		require.True(t, ok, "expected Authorization: Basic header")
		assert.Equal(t, clientID, user)
		assert.Equal(t, clientSecret, pass, "client secret must be raw, not url.QueryEscape-d")

		// Confirm the wire header is not the QueryEscaped form oauth2 would send.
		authHeader := r.Header.Get("Authorization")
		require.True(t, strings.HasPrefix(authHeader, "Basic "))
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authHeader, "Basic "))
		require.NoError(t, err)
		assert.Equal(t, clientID+":"+clientSecret, string(decoded))
		assert.NotContains(t, string(decoded), "%2B")
		assert.NotContains(t, string(decoded), "%2F")
		assert.NotContains(t, string(decoded), "%3D")

		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		values, err := url.ParseQuery(string(body))
		require.NoError(t, err)
		assert.Equal(t, "authorization_code", values.Get("grant_type"))
		assert.Equal(t, authCode, values.Get("code"))
		assert.Equal(t, "https://myapp.com/callback", values.Get("redirect_uri"))
		assert.Equal(t, "pkce-verifier", values.Get("code_verifier"))
		assert.Empty(t, values.Get("client_secret"), "secret must not be in the body (no client_secret_post fallback)")

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  "access-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
			"refresh_token": "refresh-token",
			"id_token":      "id-token",
		})
	}))
	defer server.Close()

	cfg := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  "https://myapp.com/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:   server.URL + "/authorize",
			TokenURL:  server.URL + "/token",
			AuthStyle: oauth2.AuthStyleInHeader,
		},
	}

	tok, err := exchangeAuthorizationCode(context.Background(), cfg, authCode, oauth2.VerifierOption("pkce-verifier"))
	require.NoError(t, err)
	require.NotNil(t, tok)
	assert.Equal(t, "access-token", tok.AccessToken)
	assert.Equal(t, "refresh-token", tok.RefreshToken)
	assert.Equal(t, "id-token", tok.Extra("id_token"))
	assert.Equal(t, int32(1), requestCount.Load(), "must not auto-detect/retry as client_secret_post")
}

func TestExchangeAuthorizationCode_SurfacesFirstError(t *testing.T) {
	var requestCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"invalid_client_credentials"}`))
	}))
	defer server.Close()

	cfg := &oauth2.Config{
		ClientID:     "client",
		ClientSecret: "sec+ret",
		RedirectURL:  "https://myapp.com/callback",
		Endpoint: oauth2.Endpoint{
			TokenURL:  server.URL + "/token",
			AuthStyle: oauth2.AuthStyleAutoDetect, // exchangeAuthorizationCode must override this
		},
	}

	_, err := exchangeAuthorizationCode(context.Background(), cfg, "code")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_client")
	assert.Equal(t, int32(1), requestCount.Load(), "AuthStyleAutoDetect must not trigger a second attempt")
}

func TestCustomOAuthProvider_GetOAuthToken_UsesRawBasicAuth(t *testing.T) {
	const clientSecret = "a+b/c=d"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		require.True(t, ok)
		assert.Equal(t, "client-id", user)
		assert.Equal(t, clientSecret, pass)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "tok",
			"token_type":   "Bearer",
			"expires_in":   60,
		})
	}))
	defer server.Close()

	provider := NewCustomOAuthProvider(
		"client-id",
		clientSecret,
		server.URL+"/authorize",
		server.URL+"/token",
		server.URL+"/userinfo",
		"https://myapp.com/callback",
		[]string{"openid"},
		false,
		nil,
		nil,
		nil,
		nil,
	)
	assert.Equal(t, oauth2.AuthStyleInHeader, provider.config.Endpoint.AuthStyle)

	tok, err := provider.GetOAuthToken(context.Background(), "code")
	require.NoError(t, err)
	assert.Equal(t, "tok", tok.AccessToken)
}
