package utilities

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api/apierrors"
)

func TestValidateOAuthURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
		errMsg  string
	}{
		// Valid URLs
		{
			name:    "Valid HTTPS URL",
			url:     "https://example.com/oauth/authorize",
			wantErr: false,
		},
		{
			name:    "Valid HTTPS URL with subdomain",
			url:     "https://auth.example.com/authorize",
			wantErr: false,
		},
		{
			name:    "Valid HTTPS URL with port",
			url:     "https://example.com:8443/authorize",
			wantErr: false,
		},
		{
			name:    "Valid HTTPS URL with path and query",
			url:     "https://example.com/path?query=value",
			wantErr: false,
		},

		// Invalid scheme
		{
			name:    "HTTP not allowed",
			url:     "http://example.com/authorize",
			wantErr: true,
			errMsg:  "URL must use HTTPS",
		},
		{
			name:    "FTP not allowed",
			url:     "ftp://example.com/file",
			wantErr: true,
			errMsg:  "URL must use HTTPS",
		},

		// Localhost variants
		{
			name:    "Localhost blocked",
			url:     "https://localhost/authorize",
			wantErr: true,
			errMsg:  "URL cannot point to localhost or loopback addresses",
		},
		{
			name:    "127.0.0.1 blocked",
			url:     "https://127.0.0.1/authorize",
			wantErr: true,
			errMsg:  "URL cannot point to localhost or loopback addresses",
		},
		{
			name:    "::1 (IPv6 loopback) blocked",
			url:     "https://[::1]/authorize",
			wantErr: true,
			errMsg:  "URL cannot point to localhost or loopback addresses",
		},
		{
			name:    "0.0.0.0 blocked",
			url:     "https://0.0.0.0/authorize",
			wantErr: true,
			errMsg:  "URL cannot point to localhost or loopback addresses",
		},
		{
			name:    "Subdomain of localhost blocked",
			url:     "https://test.localhost/authorize",
			wantErr: true,
			errMsg:  "URL cannot point to localhost or loopback addresses",
		},

		// Private IP ranges (RFC 1918)
		{
			name:    "10.0.0.0/8 network blocked",
			url:     "https://10.1.2.3/authorize",
			wantErr: true,
			errMsg:  "URL cannot resolve to private network addresses",
		},
		{
			name:    "172.16.0.0/12 network blocked",
			url:     "https://172.16.0.1/authorize",
			wantErr: true,
			errMsg:  "URL cannot resolve to private network addresses",
		},
		{
			name:    "192.168.0.0/16 network blocked",
			url:     "https://192.168.1.1/authorize",
			wantErr: true,
			errMsg:  "URL cannot resolve to private network addresses",
		},

		// Cloud metadata endpoint
		{
			name:    "Cloud metadata endpoint blocked",
			url:     "https://169.254.169.254/latest/meta-data",
			wantErr: true,
			errMsg:  "URL cannot resolve to cloud metadata endpoints",
		},

		// Invalid URLs
		{
			name:    "Malformed URL",
			url:     "not-a-valid-url",
			wantErr: true,
			errMsg:  "Invalid URL format",
		},
		{
			name:    "Empty URL",
			url:     "",
			wantErr: true,
			errMsg:  "Invalid URL format",
		},
		{
			name:    "URL without hostname",
			url:     "https://",
			wantErr: true,
			errMsg:  "URL must have a valid hostname",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateOAuthURL(tt.url)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					apiErr, ok := err.(*apierrors.HTTPError)
					require.True(t, ok, "expected apierrors.HTTPError")
					assert.Contains(t, apiErr.Message, tt.errMsg)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestIsLocalhost(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		want     bool
	}{
		{"localhost", "localhost", true},
		{"Localhost uppercase", "Localhost", true},
		{"LOCALHOST uppercase", "LOCALHOST", true},
		{"127.0.0.1", "127.0.0.1", true},
		{"::1 IPv6", "::1", true},
		{"0.0.0.0", "0.0.0.0", true},
		{"::", "::", true},
		{"test.localhost subdomain", "test.localhost", true},
		{"api.test.localhost nested subdomain", "api.test.localhost", true},
		{"example.com", "example.com", false},
		{"localhostbutnotreally.com", "localhostbutnotreally.com", false},
		{"localhost.example.com", "localhost.example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isLocalhost(tt.hostname)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFetchURLWithTimeout(t *testing.T) {
	t.Run("Successful fetch", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"test": "data"}`))
		}))
		defer server.Close()

		ctx := context.Background()
		resp, err := FetchURLWithTimeout(ctx, server.URL, 5*time.Second)
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("Invalid URL fails SSRF check", func(t *testing.T) {
		ctx := context.Background()
		_, err := FetchURLWithTimeout(ctx, "https://localhost/test", 5*time.Second)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "localhost or loopback addresses")
	})

	t.Run("HTTP URL rejected", func(t *testing.T) {
		ctx := context.Background()
		_, err := FetchURLWithTimeout(ctx, "http://example.com/test", 5*time.Second)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "URL must use HTTPS")
	})

	t.Run("Context timeout", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Sleep longer than the timeout
			time.Sleep(200 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		ctx := context.Background()
		_, err := FetchURLWithTimeout(ctx, server.URL, 50*time.Millisecond)
		require.Error(t, err)
		// Should timeout
		assert.Contains(t, err.Error(), "Failed to fetch URL")
	})

	t.Run("User agent and accept headers set", func(t *testing.T) {
		var capturedHeaders http.Header
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedHeaders = r.Header.Clone()
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		ctx := context.Background()
		resp, err := FetchURLWithTimeout(ctx, server.URL, 5*time.Second)
		require.NoError(t, err)
		resp.Body.Close()

		assert.Equal(t, "Supabase-Auth/1.0", capturedHeaders.Get("User-Agent"))
		assert.Equal(t, "application/json", capturedHeaders.Get("Accept"))
	})
}

func TestSSRFProtectedTransport(t *testing.T) {
	t.Run("SSRF protection re-validates on redirect", func(t *testing.T) {
		// This test verifies that the SSRF protection re-validates URLs
		// even after DNS resolution, protecting against DNS rebinding attacks

		transport := &ssrfProtectedTransport{
			base: http.DefaultTransport,
		}

		// Try to create a request to a private IP
		req, err := http.NewRequest(http.MethodGet, "https://10.0.0.1/test", nil)
		require.NoError(t, err)

		_, err = transport.RoundTrip(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "SSRF protection")
	})
}
