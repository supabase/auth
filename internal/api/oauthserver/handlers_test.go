package oauthserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/storage/test"
)

const oauthServerTestConfig = "../../../hack/test.env"

type OAuthClientTestSuite struct {
	suite.Suite
	Server *Server
	Config *conf.GlobalConfiguration
	DB     *storage.Connection
}

func TestOAuthClientHandler(t *testing.T) {
	globalConfig, err := conf.LoadGlobal(oauthServerTestConfig)
	require.NoError(t, err)

	conn, err := test.SetupDBConnection(globalConfig)
	require.NoError(t, err)

	// Enable OAuth dynamic client registration for tests
	globalConfig.OAuthServer.AllowDynamicRegistration = true

	server := NewServer(globalConfig, conn)

	ts := &OAuthClientTestSuite{
		Server: server,
		Config: globalConfig,
		DB:     conn,
	}
	defer ts.DB.Close()

	suite.Run(t, ts)
}

func (ts *OAuthClientTestSuite) SetupTest() {
	if ts.DB != nil {
		models.TruncateAll(ts.DB)
	}
	// Enable OAuth dynamic client registration for tests
	ts.Config.OAuthServer.AllowDynamicRegistration = true
}

// Helper function to create test OAuth client
func (ts *OAuthClientTestSuite) createTestOAuthClient() (*models.OAuthServerClient, string) {
	params := &OAuthServerClientRegisterParams{
		ClientName:       "Test Client",
		RedirectURIs:     []string{"https://example.com/callback", "http://localhost:3000/callback"},
		RegistrationType: "dynamic",
	}

	ctx := context.Background()
	client, secret, err := ts.Server.registerOAuthServerClient(ctx, params)
	require.NoError(ts.T(), err)
	require.NotNil(ts.T(), client)
	require.NotEmpty(ts.T(), secret)

	return client, secret
}

// HTTP Handler Tests
func (ts *OAuthClientTestSuite) TestAdminOAuthServerClientRegisterHandler() {
	// Create request payload
	payload := OAuthServerClientRegisterParams{
		ClientName:   "Test Admin Client",
		RedirectURIs: []string{"https://example.com/callback"},
	}

	body, err := json.Marshal(payload)
	require.NoError(ts.T(), err)

	// Create HTTP request
	req := httptest.NewRequest(http.MethodPost, "/admin/oauth/clients", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	// Create response recorder
	w := httptest.NewRecorder()

	// Call handler
	err = ts.Server.AdminOAuthServerClientRegister(w, req)
	require.NoError(ts.T(), err)

	// Check response
	assert.Equal(ts.T(), http.StatusCreated, w.Code)

	var response OAuthServerClientResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(ts.T(), err)

	assert.NotEmpty(ts.T(), response.ID)
	assert.NotEmpty(ts.T(), response.ClientID)
	assert.NotEmpty(ts.T(), response.ClientSecret) // Should be included in registration response
	assert.Equal(ts.T(), "Test Admin Client", response.ClientName)
	assert.Equal(ts.T(), []string{"https://example.com/callback"}, response.RedirectURIs)
	assert.Equal(ts.T(), "manual", response.RegistrationType) // Admin registration is manual
}

func (ts *OAuthClientTestSuite) TestOAuthServerClientDynamicRegisterHandler() {
	payload := OAuthServerClientRegisterParams{
		ClientName:   "Test Dynamic Client",
		RedirectURIs: []string{"https://app.example.com/callback"},
		ClientURI:    "https://app.example.com",
	}

	body, err := json.Marshal(payload)
	require.NoError(ts.T(), err)

	req := httptest.NewRequest(http.MethodPost, "/oauth/clients/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()

	err = ts.Server.OAuthServerClientDynamicRegister(w, req)
	require.NoError(ts.T(), err)

	assert.Equal(ts.T(), http.StatusCreated, w.Code)

	var response OAuthServerClientResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(ts.T(), err)

	assert.NotEmpty(ts.T(), response.ID)
	assert.NotEmpty(ts.T(), response.ClientID)
	assert.NotEmpty(ts.T(), response.ClientSecret) // Should be included in registration response
	assert.Equal(ts.T(), "Test Dynamic Client", response.ClientName)
	assert.Equal(ts.T(), "https://app.example.com", response.ClientURI)
	assert.Equal(ts.T(), "dynamic", response.RegistrationType) // Dynamic registration
}

func (ts *OAuthClientTestSuite) TestOAuthServerClientDynamicRegisterDisabled() {
	// Disable dynamic registration
	ts.Config.OAuthServer.AllowDynamicRegistration = false

	payload := OAuthServerClientRegisterParams{
		ClientName:   "Test Client",
		RedirectURIs: []string{"https://example.com/callback"},
	}

	body, err := json.Marshal(payload)
	require.NoError(ts.T(), err)

	req := httptest.NewRequest(http.MethodPost, "/oauth/clients/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()

	// Call handler - should return error
	err = ts.Server.OAuthServerClientDynamicRegister(w, req)
	require.Error(ts.T(), err)
	assert.Contains(ts.T(), err.Error(), "Dynamic client registration is not enabled")
}

func (ts *OAuthClientTestSuite) TestOAuthServerClientGetHandler() {
	client, _ := ts.createTestOAuthClient()

	req := httptest.NewRequest(http.MethodGet, "/admin/oauth/clients/"+client.ClientID, nil)

	ctx := WithOAuthServerClient(req.Context(), client)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()

	err := ts.Server.OAuthServerClientGet(w, req)
	require.NoError(ts.T(), err)

	assert.Equal(ts.T(), http.StatusOK, w.Code)

	var response OAuthServerClientResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(ts.T(), err)

	assert.Equal(ts.T(), client.ID.String(), response.ID)
	assert.Equal(ts.T(), client.ClientID, response.ClientID)
	assert.Empty(ts.T(), response.ClientSecret) // Should NOT be included in get response
	assert.Equal(ts.T(), "Test Client", response.ClientName)
}

func (ts *OAuthClientTestSuite) TestOAuthServerClientDeleteHandler() {
	// Create a test client first
	client, _ := ts.createTestOAuthClient()

	// Create HTTP request with client in context
	req := httptest.NewRequest(http.MethodDelete, "/admin/oauth/clients/"+client.ClientID, nil)

	// Add client to context (normally done by LoadOAuthServerClient middleware)
	ctx := WithOAuthServerClient(req.Context(), client)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()

	err := ts.Server.OAuthServerClientDelete(w, req)
	require.NoError(ts.T(), err)

	assert.Equal(ts.T(), http.StatusNoContent, w.Code)
	assert.Empty(ts.T(), w.Body.String())

	// Verify client was soft-deleted
	deletedClient, err := ts.Server.getOAuthServerClient(context.Background(), client.ClientID)
	assert.Error(ts.T(), err) // it was soft-deleted
	assert.Nil(ts.T(), deletedClient)
}

func (ts *OAuthClientTestSuite) TestOAuthServerClientListHandler() {
	// Create a couple test clients first
	client1, _ := ts.createTestOAuthClient()
	client2, _ := ts.createTestOAuthClient()

	req := httptest.NewRequest(http.MethodGet, "/admin/oauth/clients", nil)

	w := httptest.NewRecorder()

	err := ts.Server.OAuthServerClientList(w, req)
	require.NoError(ts.T(), err)

	assert.Equal(ts.T(), http.StatusOK, w.Code)

	var response OAuthServerClientListResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(ts.T(), err)

	assert.Len(ts.T(), response.Clients, 2)

	// Check that both clients are in the response (order might vary)
	clientIDs := []string{response.Clients[0].ClientID, response.Clients[1].ClientID}
	assert.Contains(ts.T(), clientIDs, client1.ClientID)
	assert.Contains(ts.T(), clientIDs, client2.ClientID)

	// Verify client secrets are not included in list response
	for _, client := range response.Clients {
		assert.Empty(ts.T(), client.ClientSecret)
	}
}

func (ts *OAuthClientTestSuite) TestHandlerValidation() {
	// Test invalid JSON body
	req := httptest.NewRequest(http.MethodPost, "/admin/oauth/clients", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	err := ts.Server.AdminOAuthServerClientRegister(w, req)
	require.Error(ts.T(), err)
	assert.Contains(ts.T(), err.Error(), "Invalid JSON body")

	// Test validation failure
	payload := OAuthServerClientRegisterParams{
		ClientName:   "Test Client",
		RedirectURIs: []string{"invalid-uri"}, // Invalid URI
	}

	body, err := json.Marshal(payload)
	require.NoError(ts.T(), err)

	req = httptest.NewRequest(http.MethodPost, "/admin/oauth/clients", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w = httptest.NewRecorder()
	err = ts.Server.AdminOAuthServerClientRegister(w, req)
	require.Error(ts.T(), err)
	assert.Contains(ts.T(), err.Error(), "invalid redirect_uri")
}
