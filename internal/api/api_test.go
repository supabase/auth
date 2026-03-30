package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/crypto"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/storage/test"
)

const (
	apiTestVersion = "1"
	apiTestConfig  = "../../hack/test.env"
)

func init() {
	crypto.PasswordHashCost = crypto.QuickHashCost
}

// setupAPIForTest creates a new API to run tests with.
// Using this function allows us to keep track of the database connection
// and cleaning up data between tests.
func setupAPIForTest(opts ...Option) (*API, *conf.GlobalConfiguration, error) {
	config, err := conf.LoadGlobal(apiTestConfig)
	if err != nil {
		return nil, nil, err
	}

	conn, err := test.SetupDBConnection(config)
	if err != nil {
		return nil, nil, err
	}

	return NewAPIWithVersion(config, conn, apiTestVersion, opts...), config, nil
}

func setupAPIForTestWithCallback(cb func(*conf.GlobalConfiguration, *storage.Connection)) (*API, *conf.GlobalConfiguration, error) {
	config, err := conf.LoadGlobal(apiTestConfig)
	if err != nil {
		return nil, nil, err
	}

	if cb != nil {
		cb(config, nil)
	}

	conn, err := test.SetupDBConnection(config)
	if err != nil {
		return nil, nil, err
	}

	if cb != nil {
		cb(nil, conn)
	}

	limiterOpts := NewLimiterOptions(config)
	return NewAPIWithVersion(config, conn, apiTestVersion, limiterOpts), config, nil
}

func TestEmailEnabledByDefault(t *testing.T) {
	api, _, err := setupAPIForTest()
	require.NoError(t, err)

	require.True(t, api.config.External.Email.Enabled)
}

func TestOAuthServerDisabledByDefault(t *testing.T) {
	api, _, err := setupAPIForTest()
	require.NoError(t, err)

	// OAuth server should be disabled by default
	require.False(t, api.config.OAuthServer.Enabled)

	// OAuth server instance should not be initialized when disabled
	require.Nil(t, api.oauthServer)
}

func TestNotFoundJSON(t *testing.T) {
	api, _, err := setupAPIForTest()
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "http://localhost/does-not-exist", nil)
	w := httptest.NewRecorder()
	api.handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusNotFound, w.Code)
	require.Contains(t, w.Header().Get("Content-Type"), "application/json")

	var body map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	require.Equal(t, "route_not_found", body["error_code"])
}

func TestMethodNotAllowedJSON(t *testing.T) {
	api, _, err := setupAPIForTest()
	require.NoError(t, err)

	// /settings only has GET registered, so PATCH should be method not allowed
	req := httptest.NewRequest(http.MethodPatch, "http://localhost/settings", nil)
	w := httptest.NewRecorder()
	api.handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusMethodNotAllowed, w.Code)
	require.Contains(t, w.Header().Get("Content-Type"), "application/json")

	var body map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	require.Equal(t, "method_not_allowed", body["error_code"])
}

func TestOAuthServerCanBeEnabled(t *testing.T) {
	api, _, err := setupAPIForTestWithCallback(func(config *conf.GlobalConfiguration, conn *storage.Connection) {
		if config != nil {
			// Enable OAuth server
			config.OAuthServer.Enabled = true
		}
	})
	require.NoError(t, err)

	// OAuth server should be enabled
	require.True(t, api.config.OAuthServer.Enabled)

	// OAuth server instance should be initialized when enabled
	require.NotNil(t, api.oauthServer)
}
