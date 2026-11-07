package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

func setupAPIForClientIDMetadataDocuments(t *testing.T, enabled bool) *API {
	api, _, err := setupAPIForTestWithCallback(func(config *conf.GlobalConfiguration, conn *storage.Connection) {
		if config != nil {
			config.OAuthServer.Enabled = true
			config.OAuthServer.AllowClientIDMetadataDocuments = enabled
		}
		if conn != nil {
			require.NoError(t, models.TruncateAll(conn))
		}
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = api.db.Close() })
	return api
}

func TestClientIDMetadataDocumentServerMetadata(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		api := setupAPIForClientIDMetadataDocuments(t, enabled)

		req := httptest.NewRequest(http.MethodGet, "http://localhost/.well-known/oauth-authorization-server", nil)
		w := httptest.NewRecorder()
		api.handler.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())

		var body map[string]interface{}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
		supported, ok := body["client_id_metadata_document_supported"]
		if enabled {
			assert.Equal(t, true, supported)
		} else {
			assert.False(t, ok, "should not be advertised when disabled")
		}
	}
}

func TestOAuthTokenAcceptsClientIDURL(t *testing.T) {
	const clientIDURL = "https://mcp-client.example.com/client.json"

	postToken := func(api *API, clientID string) (int, map[string]interface{}) {
		form := url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {"not-a-refresh-token"},
			"client_id":     {clientID},
		}
		req := httptest.NewRequest(http.MethodPost, "http://localhost/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		api.handler.ServeHTTP(w, req)

		var body map[string]interface{}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
		return w.Code, body
	}

	t.Run("known client passes client authentication", func(t *testing.T) {
		api := setupAPIForClientIDMetadataDocuments(t, true)

		client := &models.OAuthServerClient{
			ID:                      uuid.Must(uuid.NewV4()),
			RegistrationType:        models.OAuthServerRegistrationTypeMetadataDocument,
			ClientType:              models.OAuthServerClientTypePublic,
			TokenEndpointAuthMethod: models.TokenEndpointAuthMethodNone,
			ClientIDURL:             func() *string { s := clientIDURL; return &s }(),
		}
		client.SetRedirectURIs([]string{"https://example.com/callback"})
		client.SetGrantTypes([]string{"authorization_code", "refresh_token"})
		require.NoError(t, models.CreateOAuthServerClient(api.db, client))

		// The client is authenticated, so the request fails on the refresh token instead
		code, body := postToken(api, clientIDURL)
		assert.Equal(t, http.StatusBadRequest, code)
		assert.Equal(t, "refresh_token_not_found", body["error_code"], body)
	})

	t.Run("unknown client is rejected", func(t *testing.T) {
		api := setupAPIForClientIDMetadataDocuments(t, true)

		code, body := postToken(api, clientIDURL)
		assert.Equal(t, http.StatusBadRequest, code)
		assert.Equal(t, "Invalid client credentials", body["msg"], body)
	})

	t.Run("URL client_id is rejected when disabled", func(t *testing.T) {
		api := setupAPIForClientIDMetadataDocuments(t, false)

		code, body := postToken(api, clientIDURL)
		assert.Equal(t, http.StatusBadRequest, code)
		assert.Equal(t, "Invalid client_id format", body["msg"], body)
	})
}
