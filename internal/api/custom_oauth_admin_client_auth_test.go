package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/models"
)

// enableClientAssertions turns the experimental flag on with a signing key
// configured. The key itself is never used by the admin API.
func (ts *CustomOAuthAdminTestSuite) enableClientAssertions() {
	ts.Config.Experimental.ClientAssertion.Enabled = true
	ts.Config.Experimental.ClientAssertion.SigningKey = func(context.Context) (any, error) {
		return nil, nil
	}
}

// stubOIDCDiscovery lets OIDC providers be created without network access.
func (ts *CustomOAuthAdminTestSuite) stubOIDCDiscovery() {
	original := fetchOIDCDiscovery
	fetchOIDCDiscovery = func(_ context.Context, _ string, issuer string) (*models.OIDCDiscovery, error) {
		return &models.OIDCDiscovery{
			Issuer:                issuer,
			AuthorizationEndpoint: issuer + "/authorize",
			TokenEndpoint:         issuer + "/token",
			JwksURI:               issuer + "/jwks",
		}, nil
	}
	ts.T().Cleanup(func() { fetchOIDCDiscovery = original })
}

func (ts *CustomOAuthAdminTestSuite) adminRequest(method, path string, payload any) *httptest.ResponseRecorder {
	var body bytes.Buffer
	if payload != nil {
		require.NoError(ts.T(), json.NewEncoder(&body).Encode(payload))
	}
	req := httptest.NewRequest(method, path, &body)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	return w
}

func (ts *CustomOAuthAdminTestSuite) requireBadRequest(w *httptest.ResponseRecorder, msg string) {
	require.Equal(ts.T(), http.StatusBadRequest, w.Code, w.Body.String())
	var apiErr apierrors.HTTPError
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&apiErr))
	assert.Equal(ts.T(), apierrors.ErrorCodeValidationFailed, apiErr.ErrorCode)
	assert.Contains(ts.T(), apiErr.Message, msg)
}

func privateKeyJWTPayload(identifier string) map[string]any {
	return map[string]any{
		"provider_type":      "oidc",
		"identifier":         identifier,
		"name":               "Private Key JWT Provider",
		"client_id":          "test-client-id",
		"issuer":             "https://example.com",
		"client_auth_method": "private_key_jwt",
	}
}

func (ts *CustomOAuthAdminTestSuite) findProvider(identifier string) *models.CustomOAuthProvider {
	provider, err := models.FindCustomOAuthProviderByIdentifier(ts.API.db, identifier)
	require.NoError(ts.T(), err)
	return provider
}

// decodeRaw decodes a JSON response into a map so the test can check which
// keys are present.
func decodeRaw(ts *CustomOAuthAdminTestSuite, w *httptest.ResponseRecorder) map[string]any {
	var raw map[string]any
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&raw))
	return raw
}

func (ts *CustomOAuthAdminTestSuite) TestClientAuthFlagOff() {
	ts.stubOIDCDiscovery()

	ts.Run("create with private_key_jwt", func() {
		w := ts.adminRequest(http.MethodPost, "/admin/custom-providers", privateKeyJWTPayload("custom:pkjwt-flag-off"))
		ts.requireBadRequest(w, "private_key_jwt client authentication is not enabled")
	})

	ts.Run("create with client_assertion_audience", func() {
		payload := ts.createTestOAuth2Payload("custom:audience-flag-off")
		payload["client_assertion_audience"] = "https://example.com"
		w := ts.adminRequest(http.MethodPost, "/admin/custom-providers", payload)
		ts.requireBadRequest(w, "private_key_jwt client authentication is not enabled")
	})

	ts.Run("switch an existing provider to private_key_jwt", func() {
		provider := ts.createOIDCProviderInDB("switch-flag-off", "https://switch-flag-off.example.com")
		w := ts.adminRequest(http.MethodPut, "/admin/custom-providers/"+provider.Identifier, map[string]any{
			"client_auth_method": "private_key_jwt",
		})
		ts.requireBadRequest(w, "private_key_jwt client authentication is not enabled")
		assert.Equal(ts.T(), models.ClientAuthMethodClientSecret, ts.findProvider(provider.Identifier).ClientAuthMethod)
	})

	ts.Run("flag on without a signing key", func() {
		ts.Config.Experimental.ClientAssertion.Enabled = true
		defer func() { ts.Config.Experimental.ClientAssertion.Enabled = false }()

		w := ts.adminRequest(http.MethodPost, "/admin/custom-providers", privateKeyJWTPayload("custom:pkjwt-no-key"))
		ts.requireBadRequest(w, "private_key_jwt client authentication is not enabled")
	})

	ts.Run("client_secret providers still work", func() {
		w := ts.adminRequest(http.MethodPost, "/admin/custom-providers", ts.createTestOAuth2Payload("custom:secret-flag-off"))
		require.Equal(ts.T(), http.StatusCreated, w.Code, w.Body.String())
		assert.Equal(ts.T(), "client_secret", decodeRaw(ts, w)["client_auth_method"])
	})
}

func (ts *CustomOAuthAdminTestSuite) TestClientAuthCreateValidation() {
	ts.enableClientAssertions()
	ts.stubOIDCDiscovery()

	withSecret := privateKeyJWTPayload("custom:pkjwt-with-secret")
	withSecret["client_secret"] = "test-client-secret"

	oauth2 := ts.createTestOAuth2Payload("custom:pkjwt-oauth2")
	delete(oauth2, "client_secret")
	oauth2["client_auth_method"] = "private_key_jwt"

	unknownMethod := ts.createTestOAuth2Payload("custom:unknown-method")
	unknownMethod["client_auth_method"] = "client_secret_jwt"

	missingSecret := ts.createTestOAuth2Payload("custom:missing-secret")
	delete(missingSecret, "client_secret")

	secretWithAudience := ts.createTestOAuth2Payload("custom:secret-with-audience")
	secretWithAudience["client_assertion_audience"] = "https://example.com"

	longAudience := privateKeyJWTPayload("custom:long-audience")
	longAudience["client_assertion_audience"] = "https://issuer.example.com/" + strings.Repeat("a", 2048)

	cases := []struct {
		name    string
		payload map[string]any
		msg     string
	}{
		{"private_key_jwt with a client secret", withSecret, "client_secret must not be set"},
		{"private_key_jwt on an OAuth2 provider", oauth2, "only supported for OIDC providers"},
		{"unknown client_auth_method", unknownMethod, "client_auth_method must be either"},
		{"client_secret without a secret", missingSecret, "client_secret is required"},
		{"client_secret with an audience", secretWithAudience, "client_assertion_audience is only supported"},
		{"audience over 2048 characters", longAudience, "at most 2048 characters"},
	}
	for _, tc := range cases {
		ts.Run(tc.name, func() {
			w := ts.adminRequest(http.MethodPost, "/admin/custom-providers", tc.payload)
			ts.requireBadRequest(w, tc.msg)
		})
	}

	count, err := models.CountCustomOAuthProviders(ts.API.db)
	require.NoError(ts.T(), err)
	assert.Equal(ts.T(), 0, count)
}

func (ts *CustomOAuthAdminTestSuite) TestClientAuthCreatePrivateKeyJWT() {
	ts.enableClientAssertions()
	ts.stubOIDCDiscovery()

	payload := privateKeyJWTPayload("custom:pkjwt")
	payload["client_assertion_audience"] = "https://example.com/token"
	w := ts.adminRequest(http.MethodPost, "/admin/custom-providers", payload)
	require.Equal(ts.T(), http.StatusCreated, w.Code, w.Body.String())

	raw := decodeRaw(ts, w)
	assert.Equal(ts.T(), "private_key_jwt", raw["client_auth_method"])
	assert.Equal(ts.T(), "https://example.com/token", raw["client_assertion_audience"])
	assert.NotContains(ts.T(), raw, "client_secret")

	// no secret is stored, not even an encrypted empty string
	stored := ts.findProvider("custom:pkjwt")
	assert.Equal(ts.T(), models.ClientAuthMethodPrivateKeyJWT, stored.ClientAuthMethod)
	assert.Empty(ts.T(), stored.ClientSecret)

	// get and list return the method and audience, never the secret
	for _, path := range []string{"/admin/custom-providers/custom:pkjwt", "/admin/custom-providers"} {
		w := ts.adminRequest(http.MethodGet, path, nil)
		require.Equal(ts.T(), http.StatusOK, w.Code)
		assert.Contains(ts.T(), w.Body.String(), `"client_auth_method":"private_key_jwt"`)
		assert.Contains(ts.T(), w.Body.String(), `"client_assertion_audience":"https://example.com/token"`)
		assert.NotContains(ts.T(), w.Body.String(), "client_secret")
	}
}

func (ts *CustomOAuthAdminTestSuite) TestClientAuthSwitchMethod() {
	ts.enableClientAssertions()
	provider := ts.createOIDCProviderInDB("switch-method", "https://switch-method.example.com")
	path := "/admin/custom-providers/" + provider.Identifier

	// client_secret -> private_key_jwt clears the secret
	w := ts.adminRequest(http.MethodPut, path, map[string]any{
		"client_auth_method":        "private_key_jwt",
		"client_assertion_audience": "https://switch-method.example.com/token",
	})
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	stored := ts.findProvider(provider.Identifier)
	assert.Equal(ts.T(), models.ClientAuthMethodPrivateKeyJWT, stored.ClientAuthMethod)
	assert.Empty(ts.T(), stored.ClientSecret)
	require.NotNil(ts.T(), stored.ClientAssertionAudience)
	assert.Equal(ts.T(), "https://switch-method.example.com/token", *stored.ClientAssertionAudience)

	// a secret can't be added while the method stays private_key_jwt
	w = ts.adminRequest(http.MethodPut, path, map[string]any{"client_secret": "new-secret"})
	ts.requireBadRequest(w, "client_secret must not be set")

	// an empty audience clears the override
	w = ts.adminRequest(http.MethodPut, path, map[string]any{"client_assertion_audience": ""})
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	assert.Nil(ts.T(), ts.findProvider(provider.Identifier).ClientAssertionAudience)

	// private_key_jwt -> client_secret requires a secret
	w = ts.adminRequest(http.MethodPut, path, map[string]any{"client_auth_method": "client_secret"})
	ts.requireBadRequest(w, "client_secret is required")

	w = ts.adminRequest(http.MethodPut, path, map[string]any{
		"client_auth_method":        "private_key_jwt",
		"client_assertion_audience": "https://switch-method.example.com/token",
	})
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())

	w = ts.adminRequest(http.MethodPut, path, map[string]any{
		"client_auth_method": "client_secret",
		"client_secret":      "new-secret",
	})
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())

	stored = ts.findProvider(provider.Identifier)
	assert.Equal(ts.T(), models.ClientAuthMethodClientSecret, stored.ClientAuthMethod)
	assert.Nil(ts.T(), stored.ClientAssertionAudience, "switching to client_secret clears the audience")
	secret, err := stored.GetClientSecret(ts.Config.Security.DBEncryption)
	require.NoError(ts.T(), err)
	assert.Equal(ts.T(), "new-secret", secret)

	// updating a client_secret provider without a secret keeps the old one
	w = ts.adminRequest(http.MethodPut, path, map[string]any{"name": "Renamed"})
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
	secret, err = ts.findProvider(provider.Identifier).GetClientSecret(ts.Config.Security.DBEncryption)
	require.NoError(ts.T(), err)
	assert.Equal(ts.T(), "new-secret", secret)
}

func (ts *CustomOAuthAdminTestSuite) TestClientAuthSwitchOAuth2ToPrivateKeyJWT() {
	ts.enableClientAssertions()
	w := ts.adminRequest(http.MethodPost, "/admin/custom-providers", ts.createTestOAuth2Payload("custom:oauth2-switch"))
	require.Equal(ts.T(), http.StatusCreated, w.Code, w.Body.String())

	w = ts.adminRequest(http.MethodPut, "/admin/custom-providers/custom:oauth2-switch", map[string]any{
		"client_auth_method": "private_key_jwt",
	})
	ts.requireBadRequest(w, "only supported for OIDC providers")
}

func (ts *CustomOAuthAdminTestSuite) TestClientAuthExistingPrivateKeyJWTProviderWithFlagOff() {
	ts.enableClientAssertions()
	provider := ts.createOIDCProviderInDB("pkjwt-later-flag-off", "https://pkjwt-later-flag-off.example.com")
	path := "/admin/custom-providers/" + provider.Identifier
	w := ts.adminRequest(http.MethodPut, path, map[string]any{"client_auth_method": "private_key_jwt"})
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())

	ts.Config.Experimental.ClientAssertion.Enabled = false

	// unrelated updates still work
	w = ts.adminRequest(http.MethodPut, path, map[string]any{"name": "Renamed"})
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())

	// but nothing can (re)set private_key_jwt fields
	w = ts.adminRequest(http.MethodPut, path, map[string]any{"client_assertion_audience": "https://other.example.com"})
	ts.requireBadRequest(w, "private_key_jwt client authentication is not enabled")

	// switching back to client_secret is allowed
	w = ts.adminRequest(http.MethodPut, path, map[string]any{
		"client_auth_method": "client_secret",
		"client_secret":      "new-secret",
	})
	require.Equal(ts.T(), http.StatusOK, w.Code, w.Body.String())
}
