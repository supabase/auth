package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

// Every response from the OAuth token endpoint must carry Cache-Control:
// no-store, including errors returned by client authentication before the
// handler runs.
func TestOAuthTokenEndpointResponsesAreNotCached(t *testing.T) {
	api, _, err := setupAPIForTestWithCallback(func(c *conf.GlobalConfiguration, _ *storage.Connection) {
		if c == nil {
			return
		}
		c.OAuthServer.Enabled = true
		c.OAuthServer.AllowDynamicRegistration = true
	})
	require.NoError(t, err)
	defer api.db.Close()
	require.NoError(t, models.TruncateAll(api.db))

	body, err := json.Marshal(map[string]any{
		"client_name":                "cache test",
		"redirect_uris":              []string{"https://example.com/callback"},
		"token_endpoint_auth_method": "client_secret_basic",
	})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/oauth/clients/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var client struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &client))
	require.NotEmpty(t, client.ClientSecret)

	cases := []struct {
		name, clientID, clientSecret string
	}{
		{"wrong client secret, rejected by client authentication", client.ClientID, "wrong-secret"},
		{"unknown client, rejected by client authentication", "00000000-0000-0000-0000-000000000000", "secret"},
		{"valid client and unknown code, rejected by the handler", client.ClientID, client.ClientSecret},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			form := url.Values{"grant_type": {"authorization_code"}, "code": {"not-a-real-code"}}
			req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.SetBasicAuth(c.clientID, c.clientSecret)
			w := httptest.NewRecorder()
			api.handler.ServeHTTP(w, req)
			require.GreaterOrEqual(t, w.Code, 400, w.Body.String())
			assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
		})
	}
}
