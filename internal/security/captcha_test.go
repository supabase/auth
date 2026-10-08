package security

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
)

const (
	hcaptchaTestSecret  = "0x0000000000000000000000000000000000000000"
	turnstileTestSecret = "1x0000000000000000000000000000000AA"
	testToken           = "10000000-aaaa-bbbb-cccc-000000000001"
)

func newTestVerifier(provider, secret string) *HTTPCaptchaVerifier {
	return NewCaptchaVerifier(&conf.CaptchaConfiguration{
		Provider: provider,
		Secret:   secret,
	})
}

func TestHCaptchaSuccess(t *testing.T) {
	v := newTestVerifier("hcaptcha", hcaptchaTestSecret)
	resp, err := v.Verify(t.Context(), testToken, "127.0.0.1")
	require.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Empty(t, resp.ErrorCodes)
}

func TestHCaptchaInvalidSecret(t *testing.T) {
	v := newTestVerifier("hcaptcha", "invalid-secret")
	resp, err := v.Verify(t.Context(), testToken, "127.0.0.1")
	require.NoError(t, err)
	assert.False(t, resp.Success)
	assert.Contains(t, resp.ErrorCodes, "not-using-dummy-secret")
}

func TestTurnstileSuccess(t *testing.T) {
	v := newTestVerifier("turnstile", turnstileTestSecret)
	resp, err := v.Verify(t.Context(), testToken, "127.0.0.1")
	require.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Empty(t, resp.ErrorCodes)
}

func TestTurnstileInvalidSecret(t *testing.T) {
	v := newTestVerifier("turnstile", "invalid-secret")
	resp, err := v.Verify(t.Context(), testToken, "127.0.0.1")
	require.NoError(t, err)
	assert.False(t, resp.Success)
	assert.Contains(t, resp.ErrorCodes, "invalid-input-secret")
}

func TestUnsupportedProvider(t *testing.T) {
	v := newTestVerifier("recaptcha", "some-secret")
	_, err := v.Verify(t.Context(), testToken, "127.0.0.1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "recaptcha")
}

func TestCustomVerifyURL(t *testing.T) {
	var form map[string][]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		form = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"success": true}))
	}))
	defer server.Close()

	v := NewCaptchaVerifier(&conf.CaptchaConfiguration{
		Provider:  "turnstile",
		Secret:    turnstileTestSecret,
		VerifyURL: server.URL,
	})
	resp, err := v.Verify(t.Context(), testToken, "127.0.0.1")
	require.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Equal(t, []string{turnstileTestSecret}, form["secret"])
	assert.Equal(t, []string{testToken}, form["response"])
	assert.Equal(t, []string{"127.0.0.1"}, form["remoteip"])
}

func TestCustomVerifyURLRejection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"success":     false,
			"error-codes": []string{"invalid-input-response"},
		}))
	}))
	defer server.Close()

	v := NewCaptchaVerifier(&conf.CaptchaConfiguration{
		Provider:  "hcaptcha",
		Secret:    hcaptchaTestSecret,
		VerifyURL: server.URL,
	})
	resp, err := v.Verify(t.Context(), testToken, "127.0.0.1")
	require.NoError(t, err)
	assert.False(t, resp.Success)
	assert.Contains(t, resp.ErrorCodes, "invalid-input-response")
}
