package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	popslices "github.com/gobuffalo/pop/v6/slices"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

type CustomOAuthAdminTestSuite struct {
	suite.Suite
	API    *API
	Config *conf.GlobalConfiguration
	token  string
}

func TestCustomOAuthAdmin(t *testing.T) {
	api, config, err := setupAPIForTestWithCallback(func(config *conf.GlobalConfiguration, conn *storage.Connection) {
		if config != nil {
			// Enable custom OAuth feature before API initialization
			config.CustomOAuth.Enabled = true
			config.CustomOAuth.MaxProviders = 10
			// Ensure database encryption is enabled for tests that rely on encrypted client_secret
			config.Security.DBEncryption.Encrypt = true
		}
	})
	require.NoError(t, err)

	ts := &CustomOAuthAdminTestSuite{
		API:    api,
		Config: config,
	}
	defer api.db.Close()

	suite.Run(t, ts)
}

func (ts *CustomOAuthAdminTestSuite) SetupTest() {
	models.TruncateAll(ts.API.db)

	// Reset config to default values before each test
	// This prevents config changes from one test affecting others
	ts.Config.CustomOAuth.Enabled = true
	ts.Config.CustomOAuth.MaxProviders = 10
	ts.Config.Security.DBEncryption.Encrypt = true

	// Generate admin token
	claims := &AccessTokenClaims{
		Role: "supabase_admin",
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(ts.Config.JWT.Secret))
	require.NoError(ts.T(), err, "Error generating admin jwt")
	ts.token = token
}

// Test POST /admin/custom-providers (Create)

func (ts *CustomOAuthAdminTestSuite) TestCreateOAuth2Provider() {
	payload := map[string]interface{}{
		"provider_type":     "oauth2",
		"identifier":        "custom:github-enterprise",
		"name":              "GitHub Enterprise",
		"client_id":         "test-client-id",
		"client_secret":     "test-client-secret",
		"scopes":            []string{"read:user", "user:email"},
		"authorization_url": "https://example.com/oauth/authorize",
		"token_url":         "https://example.com/oauth/token",
		"userinfo_url":      "https://example.com/api/user",
		"pkce_enabled":      true,
		"enabled":           true,
	}

	var body bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&body).Encode(payload))

	req := httptest.NewRequest(http.MethodPost, "/admin/custom-providers", &body)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)

	require.Equal(ts.T(), http.StatusCreated, w.Code)

	var provider models.CustomOAuthProvider
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&provider))

	assert.Equal(ts.T(), models.ProviderTypeOAuth2, provider.ProviderType)
	assert.Equal(ts.T(), "custom:github-enterprise", provider.Identifier)
	assert.Equal(ts.T(), "GitHub Enterprise", provider.Name)
	assert.True(ts.T(), provider.PKCEEnabled)
	assert.True(ts.T(), provider.Enabled)

	// Ensure client secret is not exposed in JSON and is stored encrypted
	assert.Empty(ts.T(), provider.ClientSecret)
}

func (ts *CustomOAuthAdminTestSuite) TestCreateOIDCProvider() {
	payload := map[string]interface{}{
		"provider_type": "oidc",
		"identifier":    "custom:self-keycloak",
		"name":          "Keycloak",
		"client_id":     "test-client-id",
		"client_secret": "test-client-secret",
		"issuer":        "https://example.com/realms/myrealm",
		"scopes":        []string{"profile", "email"},
		"pkce_enabled":  true,
		"enabled":       true,
	}

	var body bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&body).Encode(payload))

	req := httptest.NewRequest(http.MethodPost, "/admin/custom-providers", &body)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)

	require.Equal(ts.T(), http.StatusCreated, w.Code)

	var provider models.CustomOAuthProvider
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&provider))

	assert.Equal(ts.T(), models.ProviderTypeOIDC, provider.ProviderType)
	assert.Equal(ts.T(), "custom:self-keycloak", provider.Identifier)
	assert.Contains(ts.T(), provider.Scopes, "openid") // Auto-added for OIDC
	assert.Contains(ts.T(), provider.Scopes, "profile")

	// Ensure client secret is not exposed in JSON
	assert.Empty(ts.T(), provider.ClientSecret)
}

func (ts *CustomOAuthAdminTestSuite) TestCreateProviderValidation() {
	tests := []struct {
		name       string
		payload    map[string]interface{}
		wantStatus int
		errMsg     string
	}{
		{
			name: "Missing provider_type",
			payload: map[string]interface{}{
				"identifier":    "custom:test",
				"name":          "Test",
				"client_id":     "id",
				"client_secret": "secret",
			},
			wantStatus: http.StatusBadRequest,
			errMsg:     "provider_type must be either 'oauth2' or 'oidc'",
		},
		{
			name: "Invalid provider_type",
			payload: map[string]interface{}{
				"provider_type": "invalid",
				"identifier":    "custom:test",
				"name":          "Test",
				"client_id":     "id",
				"client_secret": "secret",
			},
			wantStatus: http.StatusBadRequest,
			errMsg:     "provider_type must be either 'oauth2' or 'oidc'",
		},
		{
			name: "Missing OAuth2 required fields",
			payload: map[string]interface{}{
				"provider_type": "oauth2",
				"identifier":    "custom:test",
				"name":          "Test",
				"client_id":     "id",
				"client_secret": "secret",
				// Missing authorization_url, token_url, userinfo_url
			},
			wantStatus: http.StatusBadRequest,
			errMsg:     "authorization_url is required",
		},
		{
			name: "Missing OIDC issuer",
			payload: map[string]interface{}{
				"provider_type": "oidc",
				"identifier":    "custom:test",
				"name":          "Test",
				"client_id":     "id",
				"client_secret": "secret",
				// Missing issuer
			},
			wantStatus: http.StatusBadRequest,
			errMsg:     "issuer is required",
		},
		{
			name: "Missing custom: prefix",
			payload: map[string]interface{}{
				"provider_type":     "oauth2",
				"identifier":        "my-provider",
				"name":              "My Provider",
				"client_id":         "id",
				"client_secret":     "secret",
				"authorization_url": "https://example.com/authorize",
				"token_url":         "https://example.com/token",
				"userinfo_url":      "https://example.com/userinfo",
			},
			wantStatus: http.StatusBadRequest,
			errMsg:     "must start with 'custom:' prefix",
		},
		{
			name: "HTTP URL not allowed",
			payload: map[string]interface{}{
				"provider_type":     "oauth2",
				"identifier":        "custom:test",
				"name":              "Test",
				"client_id":         "id",
				"client_secret":     "secret",
				"authorization_url": "http://example.com/authorize",
				"token_url":         "https://example.com/token",
				"userinfo_url":      "https://example.com/userinfo",
			},
			wantStatus: http.StatusBadRequest,
			errMsg:     "URL must use HTTPS",
		},
		{
			name: "Localhost blocked (SSRF)",
			payload: map[string]interface{}{
				"provider_type":     "oauth2",
				"identifier":        "custom:test",
				"name":              "Test",
				"client_id":         "id",
				"client_secret":     "secret",
				"authorization_url": "https://example.com/authorize",
				"token_url":         "https://localhost/token",
				"userinfo_url":      "https://example.com/userinfo",
			},
			wantStatus: http.StatusBadRequest,
			errMsg:     "localhost",
		},
		{
			name: "Private IP blocked (SSRF)",
			payload: map[string]interface{}{
				"provider_type":     "oauth2",
				"identifier":        "custom:test",
				"name":              "Test",
				"client_id":         "id",
				"client_secret":     "secret",
				"authorization_url": "https://example.com/authorize",
				"token_url":         "https://10.0.0.1/token",
				"userinfo_url":      "https://example.com/userinfo",
			},
			wantStatus: http.StatusBadRequest,
			errMsg:     "private network",
		},
		{
			name: "Reserved OAuth param (client_id)",
			payload: map[string]interface{}{
				"provider_type":     "oauth2",
				"identifier":        "custom:test",
				"name":              "Test",
				"client_id":         "id",
				"client_secret":     "secret",
				"authorization_url": "https://example.com/authorize",
				"token_url":         "https://example.com/token",
				"userinfo_url":      "https://example.com/userinfo",
				"authorization_params": map[string]interface{}{
					"client_id": "overridden",
				},
			},
			wantStatus: http.StatusBadRequest,
			errMsg:     "reserved OAuth parameter",
		},
		{
			name: "Reserved OAuth param (state)",
			payload: map[string]interface{}{
				"provider_type":     "oauth2",
				"identifier":        "custom:test",
				"name":              "Test",
				"client_id":         "id",
				"client_secret":     "secret",
				"authorization_url": "https://example.com/authorize",
				"token_url":         "https://example.com/token",
				"userinfo_url":      "https://example.com/userinfo",
				"authorization_params": map[string]interface{}{
					"state": "custom",
				},
			},
			wantStatus: http.StatusBadRequest,
			errMsg:     "reserved OAuth parameter",
		},
		{
			name: "Protected system field in attribute mapping (id)",
			payload: map[string]interface{}{
				"provider_type":     "oauth2",
				"identifier":        "custom:test",
				"name":              "Test",
				"client_id":         "id",
				"client_secret":     "secret",
				"authorization_url": "https://example.com/authorize",
				"token_url":         "https://example.com/token",
				"userinfo_url":      "https://example.com/userinfo",
				"attribute_mapping": map[string]interface{}{
					"id": "external_id",
				},
			},
			wantStatus: http.StatusBadRequest,
			errMsg:     "protected system field",
		},
		{
			name: "Protected system field in attribute mapping (role)",
			payload: map[string]interface{}{
				"provider_type":     "oauth2",
				"identifier":        "custom:test",
				"name":              "Test",
				"client_id":         "id",
				"client_secret":     "secret",
				"authorization_url": "https://example.com/authorize",
				"token_url":         "https://example.com/token",
				"userinfo_url":      "https://example.com/userinfo",
				"attribute_mapping": map[string]interface{}{
					"role": "admin",
				},
			},
			wantStatus: http.StatusBadRequest,
			errMsg:     "protected system field",
		},
	}

	for _, tt := range tests {
		ts.Run(tt.name, func() {
			var body bytes.Buffer
			require.NoError(ts.T(), json.NewEncoder(&body).Encode(tt.payload))

			req := httptest.NewRequest(http.MethodPost, "/admin/custom-providers", &body)
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))

			w := httptest.NewRecorder()
			ts.API.handler.ServeHTTP(w, req)

			assert.Equal(ts.T(), tt.wantStatus, w.Code)

			if tt.errMsg != "" {
				var apiErr apierrors.HTTPError
				json.NewDecoder(w.Body).Decode(&apiErr)
				assert.Contains(ts.T(), apiErr.Message, tt.errMsg)
			}
		})
	}
}

func (ts *CustomOAuthAdminTestSuite) TestCreateProviderQuotaEnforcement() {
	// Set quota to 2
	ts.Config.CustomOAuth.MaxProviders = 2

	// Create first provider
	payload1 := ts.createTestOAuth2Payload("provider1")
	ts.createProvider(payload1, http.StatusCreated)

	// Create second provider
	payload2 := ts.createTestOAuth2Payload("provider2")
	ts.createProvider(payload2, http.StatusCreated)

	// Third provider should fail (quota exceeded)
	payload3 := ts.createTestOAuth2Payload("provider3")
	w := ts.createProvider(payload3, http.StatusBadRequest)

	var apiErr apierrors.HTTPError
	json.NewDecoder(w.Body).Decode(&apiErr)
	assert.Contains(ts.T(), apiErr.Message, "Maximum number")
}

func (ts *CustomOAuthAdminTestSuite) TestCreateProviderFeatureDisabled() {
	ts.Config.CustomOAuth.Enabled = false

	payload := ts.createTestOAuth2Payload("test")
	w := ts.createProvider(payload, http.StatusBadRequest)

	var apiErr apierrors.HTTPError
	json.NewDecoder(w.Body).Decode(&apiErr)
	assert.Contains(ts.T(), apiErr.Message, "not enabled")
}

func (ts *CustomOAuthAdminTestSuite) TestCreateProviderDuplicateIdentifier() {
	identifier := "duplicate-test"

	// Create first provider
	payload1 := ts.createTestOAuth2Payload(identifier)
	w := ts.createProvider(payload1, http.StatusCreated)
	require.Equal(ts.T(), http.StatusCreated, w.Code)

	// Try to create another provider with the same identifier
	payload2 := ts.createTestOAuth2Payload(identifier)
	w = ts.createProvider(payload2, http.StatusBadRequest)

	require.Equal(ts.T(), http.StatusBadRequest, w.Code)

	var apiErr apierrors.HTTPError
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&apiErr))
	assert.Equal(ts.T(), apierrors.ErrorCodeConflict, apiErr.ErrorCode)
	assert.Contains(ts.T(), apiErr.Message, "already exists")
	assert.Contains(ts.T(), apiErr.Message, "identifier")
}

func (ts *CustomOAuthAdminTestSuite) TestCreateProviderWithoutCustomPrefix() {
	// Test that identifiers without "custom:" prefix are rejected with a helpful error
	payload := ts.createTestOAuth2Payload("my-provider")
	// Override the identifier to not have the custom: prefix
	payload["identifier"] = "my-provider"
	w := ts.createProvider(payload, http.StatusBadRequest)

	require.Equal(ts.T(), http.StatusBadRequest, w.Code)

	var apiErr apierrors.HTTPError
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&apiErr))
	assert.Contains(ts.T(), apiErr.Message, "must start with 'custom:' prefix")
	assert.Contains(ts.T(), apiErr.Message, "custom:my-provider")
}

// Test GET /admin/custom-providers (List)

func (ts *CustomOAuthAdminTestSuite) TestListProviders() {
	// Create some providers
	ts.createProvider(ts.createTestOAuth2Payload("oauth2-1"), http.StatusCreated)
	ts.createProvider(ts.createTestOAuth2Payload("oauth2-2"), http.StatusCreated)
	ts.createProvider(ts.createTestOIDCPayload("oidc-1", "https://oidc1.example.com"), http.StatusCreated)

	req := httptest.NewRequest(http.MethodGet, "/admin/custom-providers", nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)

	require.Equal(ts.T(), http.StatusOK, w.Code)

	var response map[string]interface{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&response))

	providers := response["providers"].([]interface{})
	assert.Len(ts.T(), providers, 3)
}

func (ts *CustomOAuthAdminTestSuite) TestListProvidersEmptyReturnsArray() {
	// Without any providers created, the response should be an empty array, not null
	req := httptest.NewRequest(http.MethodGet, "/admin/custom-providers", nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)

	require.Equal(ts.T(), http.StatusOK, w.Code)

	// Verify raw JSON contains empty array, not null
	assert.Contains(ts.T(), w.Body.String(), `"providers":[]`)
}

func (ts *CustomOAuthAdminTestSuite) TestListProvidersWithTypeFilter() {
	// Create mixed providers
	ts.createProvider(ts.createTestOAuth2Payload("oauth2-1"), http.StatusCreated)
	ts.createProvider(ts.createTestOIDCPayload("oidc-1", "https://oidc1.example.com"), http.StatusCreated)
	ts.createProvider(ts.createTestOIDCPayload("oidc-2", "https://oidc2.example.com"), http.StatusCreated)

	// Filter by OAuth2
	req := httptest.NewRequest(http.MethodGet, "/admin/custom-providers?type=oauth2", nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)

	require.Equal(ts.T(), http.StatusOK, w.Code)

	var response map[string]interface{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&response))

	providers := response["providers"].([]interface{})
	assert.Len(ts.T(), providers, 1)

	// Filter by OIDC
	req = httptest.NewRequest(http.MethodGet, "/admin/custom-providers?type=oidc", nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))

	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)

	require.Equal(ts.T(), http.StatusOK, w.Code)

	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&response))

	providers = response["providers"].([]interface{})
	assert.Len(ts.T(), providers, 2)
}

// Test GET /admin/custom-providers/:id (Get)

func (ts *CustomOAuthAdminTestSuite) TestGetProvider() {
	w := ts.createProvider(ts.createTestOAuth2Payload("test-provider"), http.StatusCreated)

	var created models.CustomOAuthProvider
	json.NewDecoder(w.Body).Decode(&created)

	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/admin/custom-providers/%s", created.Identifier), nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))

	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)

	require.Equal(ts.T(), http.StatusOK, w.Code)

	var provider models.CustomOAuthProvider
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&provider))

	assert.Equal(ts.T(), created.ID, provider.ID)
	assert.Equal(ts.T(), created.Identifier, provider.Identifier)
}

func (ts *CustomOAuthAdminTestSuite) TestGetProviderNotFound() {
	// Use a valid identifier format but non-existent provider
	fakeIdentifier := "custom:non-existent-provider"

	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/admin/custom-providers/%s", fakeIdentifier), nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)

	require.Equal(ts.T(), http.StatusNotFound, w.Code)
}

// Test PUT /admin/custom-providers/:id (Update)

func (ts *CustomOAuthAdminTestSuite) TestUpdateProvider() {
	w := ts.createProvider(ts.createTestOAuth2Payload("test-provider"), http.StatusCreated)

	var created models.CustomOAuthProvider
	json.NewDecoder(w.Body).Decode(&created)

	updatePayload := map[string]interface{}{
		"name":      "Updated Name",
		"client_id": "new-client-id",
		"enabled":   false,
		"scopes":    []string{"openid", "profile", "email"},
	}

	var body bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&body).Encode(updatePayload))

	req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/admin/custom-providers/%s", created.Identifier), &body)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))

	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)

	require.Equal(ts.T(), http.StatusOK, w.Code)

	var updated models.CustomOAuthProvider
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&updated))

	assert.Equal(ts.T(), "Updated Name", updated.Name)
	assert.Equal(ts.T(), "new-client-id", updated.ClientID)
	assert.False(ts.T(), updated.Enabled)
	assert.Equal(ts.T(), popslices.String{"openid", "profile", "email"}, updated.Scopes)
}

// Test DELETE /admin/custom-providers/:id (Delete)

func (ts *CustomOAuthAdminTestSuite) TestDeleteProvider() {
	w := ts.createProvider(ts.createTestOAuth2Payload("test-provider"), http.StatusCreated)

	var created models.CustomOAuthProvider
	json.NewDecoder(w.Body).Decode(&created)

	req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/admin/custom-providers/%s", created.Identifier), nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))

	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)

	require.Equal(ts.T(), http.StatusNoContent, w.Code)

	// Verify the response body is empty (204 No Content should have no body)
	assert.Empty(ts.T(), w.Body.String())

	// Verify deletion
	req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/admin/custom-providers/%s", created.Identifier), nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))

	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)

	require.Equal(ts.T(), http.StatusNotFound, w.Code)
}

// Helper methods

func (ts *CustomOAuthAdminTestSuite) createTestOAuth2Payload(identifier string) map[string]interface{} {
	if !strings.HasPrefix(identifier, "custom:") {
		identifier = "custom:" + identifier
	}
	return map[string]interface{}{
		"provider_type":     "oauth2",
		"identifier":        identifier,
		"name":              "Test OAuth2 Provider",
		"client_id":         "test-client-id",
		"client_secret":     "test-client-secret",
		"scopes":            []string{"openid", "profile"},
		"authorization_url": "https://example.com/authorize",
		"token_url":         "https://example.com/token",
		"userinfo_url":      "https://example.com/userinfo",
		"pkce_enabled":      true,
		"enabled":           true,
	}
}

func (ts *CustomOAuthAdminTestSuite) createTestOIDCPayload(identifier, issuer string) map[string]interface{} {
	if !strings.HasPrefix(identifier, "custom:") {
		identifier = "custom:" + identifier
	}
	// If issuer is not provided or uses non-resolvable domain, use example.com
	if issuer == "" || strings.Contains(issuer, "oidc1.example.com") || strings.Contains(issuer, "oidc2.example.com") {
		issuer = "https://example.com/realms/" + identifier
	}
	return map[string]interface{}{
		"provider_type": "oidc",
		"identifier":    identifier,
		"name":          "Test OIDC Provider",
		"client_id":     "test-client-id",
		"client_secret": "test-client-secret",
		"issuer":        issuer,
		"scopes":        []string{"profile", "email"},
		"pkce_enabled":  true,
		"enabled":       true,
	}
}

func (ts *CustomOAuthAdminTestSuite) createProvider(payload map[string]interface{}, expectedStatus int) *httptest.ResponseRecorder {
	var body bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&body).Encode(payload))

	req := httptest.NewRequest(http.MethodPost, "/admin/custom-providers", &body)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)

	require.Equal(ts.T(), expectedStatus, w.Code)

	return w
}
