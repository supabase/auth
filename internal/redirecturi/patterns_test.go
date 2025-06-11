package redirecturi

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to create a config with one or more patterns inline
func mustConfig(patterns ...string) *RedirectConfig {
	var redirectPatterns []RedirectPattern
	for _, pattern := range patterns {
		p, err := CategorizePattern(pattern)
		if err != nil {
			panic("Invalid test pattern: " + pattern + ": " + err.Error())
		}
		redirectPatterns = append(redirectPatterns, p)
	}
	return NewRedirectConfig(redirectPatterns)
}

func TestCategorizePattern(t *testing.T) {
	tests := []struct {
		name         string
		pattern      string
		expectedType RedirectPatternType
		expectError  bool
		errContains  string
	}{
		// Exact URL patterns
		{
			name:         "HTTPS URL with path",
			pattern:      "https://example.com/callback",
			expectedType: PatternTypeExact,
			expectError:  false,
		},
		{
			name:         "HTTP localhost URL",
			pattern:      "http://localhost:3000/auth",
			expectedType: PatternTypeExact,
			expectError:  false,
		},
		{
			name:         "HTTPS URL with query params",
			pattern:      "https://api.example.com/auth?version=v1",
			expectedType: PatternTypeExact,
			expectError:  false,
		},
		{
			name:         "Custom scheme URL",
			pattern:      "myapp://auth/callback",
			expectedType: PatternTypeExact,
			expectError:  false,
		},
		{
			name:         "Custom scheme with simple path",
			pattern:      "myapp://login",
			expectedType: PatternTypeExact,
			expectError:  false,
		},
		{
			name:         "Custom scheme with query params",
			pattern:      "myapp://callback?token=abc",
			expectedType: PatternTypeExact,
			expectError:  false,
		},

		// Domain-only patterns
		{
			name:         "Simple domain",
			pattern:      "example.com",
			expectedType: PatternTypeDomainOnly,
			expectError:  false,
		},
		{
			name:         "Subdomain",
			pattern:      "auth.example.com",
			expectedType: PatternTypeDomainOnly,
			expectError:  false,
		},
		{
			name:         "Localhost domain",
			pattern:      "localhost",
			expectedType: PatternTypeDomainOnly,
			expectError:  false,
		},
		{
			name:         "IP address domain",
			pattern:      "127.0.0.1",
			expectedType: PatternTypeDomainOnly,
			expectError:  false,
		},

		// Scheme-only patterns
		{
			name:         "Custom app scheme",
			pattern:      "myapp://",
			expectedType: PatternTypeSchemeOnly,
			expectError:  false,
		},
		{
			name:         "Another custom scheme",
			pattern:      "com.example.app://",
			expectedType: PatternTypeSchemeOnly,
			expectError:  false,
		},
		{
			name:         "Scheme with numbers",
			pattern:      "app123://",
			expectedType: PatternTypeSchemeOnly,
			expectError:  false,
		},
		{
			name:         "Scheme with hyphens",
			pattern:      "my-app://",
			expectedType: PatternTypeSchemeOnly,
			expectError:  false,
		},
		{
			name:         "Single letter scheme",
			pattern:      "x://",
			expectedType: PatternTypeSchemeOnly,
			expectError:  false,
		},

		// Wildcard patterns
		{
			name:         "Subdomain wildcard",
			pattern:      "*.example.com",
			expectedType: PatternTypeWildcard,
			expectError:  false,
		},
		{
			name:         "Complex wildcard domain",
			pattern:      "*-preview.example.com",
			expectedType: PatternTypeWildcard,
			expectError:  false,
		},
		{
			name:         "Wildcard with https",
			pattern:      "https://*.staging.example.com",
			expectedType: PatternTypeWildcard,
			expectError:  false,
		},

		// Error cases
		{
			name:        "Empty pattern",
			pattern:     "",
			expectError: true,
			errContains: "pattern cannot be empty",
		},
		{
			name:        "Whitespace only",
			pattern:     "   ",
			expectError: true,
			errContains: "pattern cannot be empty",
		},
		{
			name:        "Wildcard in path",
			pattern:     "https://example.com/auth/*",
			expectError: true,
			errContains: "wildcards are not allowed in URL paths",
		},
		{
			name:        "Wildcard in query parameter",
			pattern:     "https://example.com/callback?param=*",
			expectError: true,
			errContains: "wildcards are not allowed in query parameters",
		},
		{
			name:        "Wildcard in fragment",
			pattern:     "https://example.com/callback#section*",
			expectError: true,
			errContains: "wildcards are not allowed in URL fragments",
		},
		{
			name:        "Invalid URL",
			pattern:     "https://[invalid",
			expectError: true,
			errContains: "invalid URL pattern",
		},
		{
			name:        "Invalid scheme in wildcard",
			pattern:     "ht*tp://example.com",
			expectError: true,
			errContains: "invalid URL pattern", // URL parsing will fail first
		},
		{
			name:        "Invalid scheme only pattern",
			pattern:     "ht[tp://",
			expectError: true,
			errContains: "invalid scheme pattern",
		},
		{
			name:        "Path in domain-only pattern",
			pattern:     "example.com/path",
			expectError: true,
			errContains: "invalid pattern format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := CategorizePattern(tt.pattern)

			if tt.expectError {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedType, result.Type)
				assert.Equal(t, tt.pattern, result.Original)
				assert.NotNil(t, result.GlobPattern)

				// Verify glob pattern is actually usable
				switch tt.expectedType {
				case PatternTypeDomainOnly:
					// Should match HTTPS version
					assert.True(t, result.GlobPattern.Match("https://"+tt.pattern+"/path"))
				case PatternTypeSchemeOnly:
					// Should match scheme with any host/path
					schemePrefix := tt.pattern
					assert.True(t, result.GlobPattern.Match(schemePrefix+"host/path"))
				case PatternTypeExact:
					// Should match exactly
					assert.True(t, result.GlobPattern.Match(tt.pattern))
				case PatternTypeWildcard:
					// Wildcard patterns should be tested individually based on their content
					// Skip generic validation here as each wildcard has specific matching rules
				}
			}
		})
	}
}

func TestIsValidRedirectURL(t *testing.T) {

	tests := []struct {
		name        string
		config      *RedirectConfig
		siteURL     string
		redirectURL string
		expected    bool
	}{
		// Basic validation
		{
			name:        "Nil config returns false",
			config:      nil,
			redirectURL: "https://example.com",
			siteURL:     "",
			expected:    false,
		},
		{
			name:        "Empty config returns false",
			config:      NewRedirectConfig([]RedirectPattern{}),
			redirectURL: "https://example.com",
			siteURL:     "",
			expected:    false,
		},
		{
			name:        "Empty URL returns false",
			config:      mustConfig("https://example.com/callback"),
			redirectURL: "",
			siteURL:     "",
			expected:    false,
		},

		// Security checks
		{
			name:        "Same hostname as site",
			config:      mustConfig("https://example.com/callback"),
			redirectURL: "https://site.com/different-path",
			siteURL:     "https://site.com",
			expected:    true,
		},
		{
			name:        "Decimal IP address",
			config:      mustConfig("https://example.com/callback"),
			redirectURL: "https://2130706433/path", // 127.0.0.1 in decimal
			siteURL:     "https://site.com",
			expected:    false,
		},
		{
			name:        "Regular IP address",
			config:      mustConfig("https://example.com/callback"),
			redirectURL: "https://192.168.1.1/path",
			siteURL:     "https://site.com",
			expected:    false,
		},
		{
			name:        "Loopback IP allowed",
			config:      mustConfig("https://example.com/callback"),
			redirectURL: "https://127.0.0.1/path",
			siteURL:     "https://site.com",
			expected:    true,
		},
		{
			name:        "IPv6 loopback",
			config:      mustConfig("https://example.com/callback"),
			redirectURL: "https://[::1]/path",
			siteURL:     "https://site.com",
			expected:    true,
		},
		{
			name:        "Malformed redirect URL",
			config:      mustConfig("https://example.com/callback"),
			redirectURL: "not-a-url",
			siteURL:     "https://site.com",
			expected:    false,
		},

		// Exact pattern matching
		{
			name:        "Exact match - valid",
			config:      mustConfig("https://example.com/callback"),
			redirectURL: "https://example.com/callback",
			siteURL:     "",
			expected:    true,
		},
		{
			name:        "Exact match - different path",
			config:      mustConfig("https://example.com/callback"),
			redirectURL: "https://example.com/other",
			siteURL:     "",
			expected:    false,
		},
		{
			name:        "Exact match - different scheme",
			config:      mustConfig("https://example.com/callback"),
			redirectURL: "http://example.com/callback",
			siteURL:     "",
			expected:    false,
		},

		// Domain-only pattern matching
		{
			name:        "Domain pattern - HTTPS with path",
			config:      mustConfig("auth.example.com"),
			redirectURL: "https://auth.example.com/login",
			siteURL:     "",
			expected:    true,
		},
		{
			name:        "Domain pattern - HTTPS root",
			config:      mustConfig("auth.example.com"),
			redirectURL: "https://auth.example.com",
			siteURL:     "",
			expected:    true,
		},
		{
			name:        "Domain pattern - HTTP not allowed",
			config:      mustConfig("auth.example.com"),
			redirectURL: "http://auth.example.com/login",
			siteURL:     "",
			expected:    false,
		},
		{
			name:        "Domain pattern - wrong domain",
			config:      mustConfig("auth.example.com"),
			redirectURL: "https://other.example.com/login",
			siteURL:     "",
			expected:    false,
		},

		// Base domain pattern matching (example.com)
		{
			name:        "Base domain - HTTPS with path",
			config:      mustConfig("example.com"),
			redirectURL: "https://example.com/login",
			siteURL:     "",
			expected:    true,
		},
		{
			name:        "Base domain - HTTPS root",
			config:      mustConfig("example.com"),
			redirectURL: "https://example.com",
			siteURL:     "",
			expected:    true,
		},
		{
			name:        "Base domain - HTTPS with deep path",
			config:      mustConfig("example.com"),
			redirectURL: "https://example.com/auth/callback/success",
			siteURL:     "",
			expected:    true,
		},
		{
			name:        "Base domain - HTTPS with query params",
			config:      mustConfig("example.com"),
			redirectURL: "https://example.com/login?redirect=home&token=abc",
			siteURL:     "",
			expected:    true,
		},
		{
			name:        "Base domain - HTTP not allowed",
			config:      mustConfig("example.com"),
			redirectURL: "http://example.com/login",
			siteURL:     "",
			expected:    false,
		},
		{
			name:        "Base domain - wrong domain (subdomain)",
			config:      mustConfig("example.com"),
			redirectURL: "https://auth.example.com/login",
			siteURL:     "",
			expected:    false,
		},
		{
			name:        "Base domain - wrong domain (different)",
			config:      mustConfig("example.com"),
			redirectURL: "https://other.com/login",
			siteURL:     "",
			expected:    false,
		},
		{
			name:        "Base domain - with fragment",
			config:      mustConfig("example.com"),
			redirectURL: "https://example.com/page#section",
			siteURL:     "",
			expected:    true,
		},
		{
			name:        "Base domain - with port",
			config:      mustConfig("example.com"),
			redirectURL: "https://example.com:8080/login",
			siteURL:     "",
			expected:    false, // Port makes it different domain
		},

		// Scheme-only pattern matching
		{
			name:        "Scheme pattern - matches any host/path",
			config:      mustConfig("myapp://"),
			redirectURL: "myapp://host/path?query=value",
			siteURL:     "",
			expected:    true,
		},
		{
			name:        "Scheme pattern - matches simple",
			config:      mustConfig("myapp://"),
			redirectURL: "myapp://callback",
			siteURL:     "",
			expected:    true,
		},
		{
			name:        "Scheme pattern - matches empty path",
			config:      mustConfig("myapp://"),
			redirectURL: "myapp://",
			siteURL:     "",
			expected:    true,
		},
		{
			name:        "Scheme pattern - matches complex path",
			config:      mustConfig("myapp://"),
			redirectURL: "myapp://auth/login/success?token=123&user=456",
			siteURL:     "",
			expected:    true,
		},
		{
			name:        "Scheme pattern - wrong scheme",
			config:      mustConfig("myapp://"),
			redirectURL: "otherapp://callback",
			siteURL:     "",
			expected:    false,
		},

		// Scheme exact pattern matching (myapp://login)
		{
			name:        "Scheme exact - matches exact path",
			config:      mustConfig("myapp://login"),
			redirectURL: "myapp://login",
			siteURL:     "",
			expected:    true,
		},
		{
			name:        "Scheme exact - does not match with additional path",
			config:      mustConfig("myapp://login"),
			redirectURL: "myapp://login/success",
			siteURL:     "",
			expected:    false,
		},
		{
			name:        "Scheme exact - does not match with query params",
			config:      mustConfig("myapp://login"),
			redirectURL: "myapp://login?token=abc",
			siteURL:     "",
			expected:    false,
		},
		{
			name:        "Scheme exact - does not match with path and query",
			config:      mustConfig("myapp://login"),
			redirectURL: "myapp://login/success?user=123",
			siteURL:     "",
			expected:    false,
		},
		{
			name:        "Scheme exact - different path",
			config:      mustConfig("myapp://login"),
			redirectURL: "myapp://callback",
			siteURL:     "",
			expected:    false,
		},
		{
			name:        "Scheme exact - wrong scheme",
			config:      mustConfig("myapp://login"),
			redirectURL: "otherapp://login",
			siteURL:     "",
			expected:    false,
		},

		// Scheme with query pattern matching
		{
			name:        "Scheme with query - exact match",
			config:      mustConfig("myapp://callback?token=abc"),
			redirectURL: "myapp://callback?token=abc",
			siteURL:     "",
			expected:    true,
		},
		{
			name:        "Scheme with query - additional query params",
			config:      mustConfig("myapp://callback?token=abc"),
			redirectURL: "myapp://callback?token=abc&user=123",
			siteURL:     "",
			expected:    false, // Additional query params are not allowed for security (exact match required)
		},
		{
			name:        "Scheme with query - different query value",
			config:      mustConfig("myapp://callback?token=abc"),
			redirectURL: "myapp://callback?token=xyz",
			siteURL:     "",
			expected:    false,
		},
		{
			name:        "Scheme with query - missing query",
			config:      mustConfig("myapp://callback?token=abc"),
			redirectURL: "myapp://callback",
			siteURL:     "",
			expected:    false,
		},

		// Custom scheme pattern matching
		{
			name:        "Custom scheme - matches with path",
			config:      mustConfig("com.example.app://"),
			redirectURL: "com.example.app://auth/callback",
			siteURL:     "",
			expected:    true,
		},
		{
			name:        "Custom scheme - matches simple",
			config:      mustConfig("com.example.app://"),
			redirectURL: "com.example.app://login",
			siteURL:     "",
			expected:    true,
		},
		{
			name:        "Custom scheme - wrong scheme",
			config:      mustConfig("com.example.app://"),
			redirectURL: "com.other.app://login",
			siteURL:     "",
			expected:    false,
		},

		// Wildcard pattern matching
		{
			name:        "Wildcard - matches subdomain",
			config:      mustConfig("*.preview.example.com"),
			redirectURL: "https://branch-123.preview.example.com/callback",
			siteURL:     "",
			expected:    true,
		},
		{
			name:        "Wildcard - matches another subdomain",
			config:      mustConfig("*.preview.example.com"),
			redirectURL: "https://staging.preview.example.com",
			siteURL:     "",
			expected:    true,
		},
		{
			name:        "Wildcard - wrong domain",
			config:      mustConfig("*.preview.example.com"),
			redirectURL: "https://preview.other.com",
			siteURL:     "",
			expected:    false,
		},

		// Multiple patterns
		{
			name: "Multiple patterns - first matches",
			config: mustConfig(
				"https://example.com/callback",
				"auth.example.com",
			),
			redirectURL: "https://example.com/callback",
			siteURL:     "",
			expected:    true,
		},
		{
			name: "Multiple patterns - second matches",
			config: mustConfig(
				"https://example.com/callback",
				"auth.example.com",
			),
			redirectURL: "https://auth.example.com/login",
			siteURL:     "",
			expected:    true,
		},
		{
			name: "Multiple patterns - none match",
			config: mustConfig(
				"https://example.com/callback",
				"auth.example.com",
			),
			redirectURL: "https://other.com/callback",
			siteURL:     "",
			expected:    false,
		},

		// Multiple scheme patterns
		{
			name: "Multiple schemes - scheme-only matches",
			config: mustConfig(
				"myapp://",
				"myapp://login",
				"com.example.app://",
			),
			redirectURL: "myapp://anything",
			siteURL:     "",
			expected:    true,
		},
		{
			name: "Multiple schemes - exact scheme does not match with additional path",
			config: mustConfig(
				"myapp://login",
				"com.example.app://",
			),
			redirectURL: "myapp://login/success",
			siteURL:     "",
			expected:    false,
		},
		{
			name: "Multiple schemes - custom scheme matches",
			config: mustConfig(
				"myapp://",
				"com.example.app://",
			),
			redirectURL: "com.example.app://callback",
			siteURL:     "",
			expected:    true,
		},
		{
			name: "Multiple schemes - no match",
			config: mustConfig(
				"myapp://login",
				"com.example.app://",
			),
			redirectURL: "differentapp://callback",
			siteURL:     "",
			expected:    false,
		},

		// Mixed pattern types
		{
			name: "Mixed patterns - HTTPS matches",
			config: mustConfig(
				"https://example.com/callback",
				"myapp://",
				"*.preview.example.com",
			),
			redirectURL: "https://example.com/callback",
			siteURL:     "",
			expected:    true,
		},
		{
			name: "Mixed patterns - scheme matches",
			config: mustConfig(
				"https://example.com/callback",
				"myapp://",
				"*.preview.example.com",
			),
			redirectURL: "myapp://login",
			siteURL:     "",
			expected:    true,
		},
		{
			name: "Mixed patterns - wildcard matches",
			config: mustConfig(
				"https://example.com/callback",
				"myapp://",
				"*.preview.example.com",
			),
			redirectURL: "https://test.preview.example.com/auth",
			siteURL:     "",
			expected:    true,
		},

		// Localhost configuration
		{
			name:        "Localhost - allow without http scheme",
			config:      mustConfig("localhost"),
			redirectURL: "http://localhost",
			siteURL:     "",
			expected:    true,
		},
		{
			name:        "Localhost - allow without https scheme",
			config:      mustConfig("localhost"),
			redirectURL: "https://localhost",
			siteURL:     "",
			expected:    true,
		},
		{
			name:        "Localhost - allow without scheme different port",
			config:      mustConfig("localhost"),
			redirectURL: "http://localhost:3000",
			siteURL:     "",
			expected:    true,
		},
		{
			name:        "Localhost - allow without scheme different port & path",
			config:      mustConfig("localhost"),
			redirectURL: "http://localhost:3000/callback",
			siteURL:     "",
			expected:    true,
		},

		// Localhost HTTP explicit configuration
		{
			name:        "Localhost HTTP - explicitly configured",
			config:      mustConfig("http://localhost:3000"),
			redirectURL: "http://localhost:3000",
			siteURL:     "",
			expected:    true,
		},
		{
			name:        "Localhost HTTP - with path does not match exact",
			config:      mustConfig("http://localhost:3000"),
			redirectURL: "http://localhost:3000/auth",
			siteURL:     "",
			expected:    false,
		},

		// Edge cases
		{
			name:        "Case sensitivity in URL",
			config:      mustConfig("https://example.com/callback"),
			redirectURL: "https://EXAMPLE.com/callback",
			siteURL:     "",
			expected:    false, // URLs are case sensitive in path/query but the glob pattern was created with lowercase
		},
		{
			name:        "URL with fragment",
			config:      mustConfig("https://example.com/callback"),
			redirectURL: "https://example.com/callback#section",
			siteURL:     "",
			expected:    false, // Fragment makes it different
		},
		{
			name:        "URL with query params",
			config:      mustConfig("auth.example.com"),
			redirectURL: "https://auth.example.com/login?redirect=home",
			siteURL:     "",
			expected:    true, // Domain patterns allow any path/query
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidRedirectURL(tt.config, tt.redirectURL, tt.siteURL)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRunShadowModeTest(t *testing.T) {
	// This is harder to test directly since it logs, but we can test it doesn't panic
	redirectConfig := mustConfig("https://example.com/callback")

	// Should not panic with valid inputs
	assert.NotPanics(t, func() {
		RunShadowModeTest(redirectConfig, "https://example.com/callback", "https://site.com", true)
	})

	// Should not panic with nil config
	assert.NotPanics(t, func() {
		RunShadowModeTest(nil, "https://example.com/callback", "https://site.com", true)
	})
}

func TestExactURLGlobEscaping(t *testing.T) {
	tests := []struct {
		name         string
		configURL    string
		redirectURL  string
		shouldMatch  bool
		description  string
	}{
		{
			name:         "Question mark in query parameter",
			configURL:    "https://example.com/callback?foo",
			redirectURL:  "https://example.com/callback?foo",
			shouldMatch:  true,
			description:  "Exact match with query parameter",
		},
		{
			name:         "Question mark should not match slash",
			configURL:    "https://example.com/callback?foo",
			redirectURL:  "https://example.com/callback/foo",
			shouldMatch:  false,
			description:  "Question mark should not act as wildcard",
		},
		{
			name:         "Brackets in query parameter",
			configURL:    "https://example.com/callback?array[0]=value",
			redirectURL:  "https://example.com/callback?array[0]=value",
			shouldMatch:  true,
			description:  "Exact match with brackets",
		},
		{
			name:         "Brackets should not match ranges",
			configURL:    "https://example.com/callback?array[0]=value",
			redirectURL:  "https://example.com/callback?array0=value",
			shouldMatch:  false,
			description:  "Brackets should not act as character class",
		},
		{
			name:         "Braces in query parameter",
			configURL:    "https://example.com/callback?json={\"key\":\"value\"}",
			redirectURL:  "https://example.com/callback?json={\"key\":\"value\"}",
			shouldMatch:  true,
			description:  "Exact match with braces",
		},
		{
			name:         "Backslash in path",
			configURL:    "https://example.com/path\\with\\backslash",
			redirectURL:  "https://example.com/path\\with\\backslash",
			shouldMatch:  true,
			description:  "Exact match with backslashes",
		},
		{
			name:         "Multiple special characters",
			configURL:    "https://example.com/callback?a=val&b=?&c=[1]&d={x}",
			redirectURL:  "https://example.com/callback?a=val&b=?&c=[1]&d={x}",
			shouldMatch:  true,
			description:  "Exact match with multiple special chars",
		},
		{
			name:         "Special characters should not act as wildcards",
			configURL:    "https://example.com/callback?a=val&b=?",
			redirectURL:  "https://example.com/callback?a=xyz&b=z",
			shouldMatch:  false,
			description:  "Special chars should be literal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := mustConfig(tt.configURL)
			result := IsValidRedirectURL(config, tt.redirectURL, "")
			assert.Equal(t, tt.shouldMatch, result, tt.description)
		})
	}
}

func TestEscapeGlobPattern(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "https://example.com/callback",
			expected: "https://example.com/callback",
		},
		{
			input:    "https://example.com/callback?foo",
			expected: "https://example.com/callback\\?foo",
		},
		{
			input:    "https://example.com/array[0]={value}",
			expected: "https://example.com/array\\[0\\]=\\{value\\}",
		},
		{
			input:    "https://example.com/path\\with\\backslash",
			expected: "https://example.com/path\\\\with\\\\backslash",
		},
		{
			input:    "*?[]{}", 
			expected: "\\*\\?\\[\\]\\{\\}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := escapeGlobPattern(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
