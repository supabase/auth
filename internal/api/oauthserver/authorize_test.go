package oauthserver

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gobwas/glob"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/hooks/v0hooks"
	"github.com/supabase/auth/internal/storage/test"
	"github.com/supabase/auth/internal/tokens"
)

func TestValidateRequestOrigin(t *testing.T) {
	// Setup test configuration
	globalConfig, err := conf.LoadGlobal(oauthServerTestConfig)
	require.NoError(t, err)

	// Set up test site URL for validation
	globalConfig.SiteURL = "https://example.com"
	globalConfig.URIAllowList = []string{
		"http://localhost:3000",
		"https://app.example.com",
	}

	// Set up URIAllowListMap manually for testing
	globalConfig.URIAllowListMap = make(map[string]glob.Glob)
	for _, uri := range globalConfig.URIAllowList {
		g := glob.MustCompile(uri, '.', '/')
		globalConfig.URIAllowListMap[uri] = g
	}

	conn, err := test.SetupDBConnection(globalConfig)
	require.NoError(t, err)
	defer conn.Close()

	hooksMgr := &v0hooks.Manager{}
	tokenService := tokens.NewService(globalConfig, hooksMgr)
	server := NewServer(globalConfig, conn, tokenService)

	tests := []struct {
		name         string
		originHeader string
		expectError  bool
		errorMessage string
	}{
		{
			name:         "Empty Origin header should be allowed",
			originHeader: "",
			expectError:  false,
		},
		{
			name:         "Valid Origin matching site URL should be allowed",
			originHeader: "https://example.com",
			expectError:  false,
		},
		{
			name:         "Valid Origin with different path should be allowed",
			originHeader: "https://example.com/some/path",
			expectError:  false,
		},
		{
			name:         "Valid Origin matching allow list should be allowed",
			originHeader: "https://app.example.com",
			expectError:  false,
		},
		{
			name:         "Valid Origin with localhost should be allowed",
			originHeader: "http://localhost:3000",
			expectError:  false,
		},
		{
			name:         "Invalid Origin should be rejected",
			originHeader: "https://malicious.com",
			expectError:  true,
			errorMessage: "unauthorized request origin",
		},
		{
			name:         "Invalid Origin with IP address should be rejected",
			originHeader: "https://192.168.1.1",
			expectError:  true,
			errorMessage: "unauthorized request origin",
		},
		{
			name:         "Valid loopback IP should be allowed",
			originHeader: "http://127.0.0.1:3000",
			expectError:  false,
		},
		{
			name:         "Invalid Origin format should be rejected",
			originHeader: "not-a-valid-url",
			expectError:  true,
			errorMessage: "unauthorized request origin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test request
			req := httptest.NewRequest(http.MethodGet, "/test", nil)

			// Set Origin header if provided
			if tt.originHeader != "" {
				req.Header.Set("Origin", tt.originHeader)
			}

			// Call validateRequestOrigin
			err := server.validateRequestOrigin(req)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMessage != "" {
					assert.Contains(t, err.Error(), tt.errorMessage)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateRequestOriginEdgeCases(t *testing.T) {
	globalConfig, err := conf.LoadGlobal(oauthServerTestConfig)
	require.NoError(t, err)

	globalConfig.SiteURL = "https://example.com"

	conn, err := test.SetupDBConnection(globalConfig)
	require.NoError(t, err)
	defer conn.Close()

	hooksMgr := &v0hooks.Manager{}
	tokenService := tokens.NewService(globalConfig, hooksMgr)
	server := NewServer(globalConfig, conn, tokenService)

	t.Run("Origin with different port should be allowed (hostname matching)", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Origin", "https://example.com:8080")

		// Should pass because hostname matches (IsRedirectURLValid allows different ports)
		err := server.validateRequestOrigin(req)
		assert.NoError(t, err)
	})

	t.Run("Case sensitivity in Origin header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Origin", "https://EXAMPLE.COM")

		// Should fail because hostname comparison is case-sensitive in URL parsing
		err := server.validateRequestOrigin(req)
		assert.Error(t, err)
	})

	t.Run("Origin with trailing slash should be handled", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Origin", "https://example.com/")

		// Should pass - URL parsing should handle trailing slash correctly
		err := server.validateRequestOrigin(req)
		assert.NoError(t, err)
	})

	t.Run("Multiple Origin headers uses first one", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		// Add multiple Origin headers
		req.Header.Add("Origin", "https://example.com")   // First header (valid)
		req.Header.Add("Origin", "https://malicious.com") // Second header (invalid)

		// Go's http.Header.Get() returns only the first header value
		// So this should pass because first Origin is valid
		err := server.validateRequestOrigin(req)
		assert.NoError(t, err)
	})

	t.Run("Comma-separated origins in single header should fail", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		// Manually create comma-separated Origin header (malformed)
		req.Header.Set("Origin", "https://example.com,https://malicious.com")

		// This should fail because comma-separated origins is not a valid Origin header format
		err := server.validateRequestOrigin(req)
		assert.Error(t, err)
	})
}
