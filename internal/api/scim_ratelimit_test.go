package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
)

func TestSCIMRateLimit(t *testing.T) {
	api, _ := setupSCIMAPI(t, func(config *conf.GlobalConfiguration) {
		config.RateLimitScim = 1
	})
	defer func() { require.NoError(t, api.db.Close()) }()
	require.NoError(t, models.TruncateAll(api.db))

	token := func() string {
		_, token := createSSOProviderWithSCIMToken(t, api.db)
		return token
	}
	tokenA, tokenB := token(), token()

	send := func(method, path, token, ip string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, nil)
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		r.Header.Set(api.config.RateLimitHeader, ip)
		w := httptest.NewRecorder()
		api.handler.ServeHTTP(w, r)
		return w
	}
	get := func(token, ip string) *httptest.ResponseRecorder {
		return send(http.MethodGet, "/scim/v2/Users", token, ip)
	}

	limited := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"detail":"Request rate limit reached","status":"429"}`
	const ip = "192.0.2.1"

	for range 30 {
		w := get(tokenA, ip)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	}
	w := get(tokenA, ip)
	require.Equal(t, http.StatusTooManyRequests, w.Code)
	require.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
	require.Equal(t, "300", w.Header().Get("Retry-After"))
	require.JSONEq(t, limited, w.Body.String())
	w = get(tokenB, ip)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	for range 30 {
		w := get("scim_invalid", ip)
		require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
	}
	for _, token := range []string{"scim_invalid", ""} {
		w := get(token, ip)
		require.Equal(t, http.StatusTooManyRequests, w.Code, w.Body.String())
		require.JSONEq(t, limited, w.Body.String())
	}
	w = get(tokenB, ip)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = get("scim_invalid", "198.51.100.1")
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())

	for i, tc := range []struct {
		method, path string
		status       int
	}{
		{http.MethodGet, "/scim/v2/ServiceProviderConfig", http.StatusOK},
		{http.MethodHead, "/scim/v2/ServiceProviderConfig", http.StatusOK},
		{http.MethodGet, "/scim/v2/Unknown", http.StatusUnauthorized},
		{http.MethodDelete, "/scim/v2/Users", http.StatusUnauthorized},
	} {
		ip := fmt.Sprintf("203.0.113.%d", i+1)
		for range 30 {
			w := send(tc.method, tc.path, "scim_invalid", ip)
			require.Equal(t, tc.status, w.Code, tc.method+" "+tc.path)
		}
		w := send(tc.method, tc.path, "scim_invalid", ip)
		require.Equal(t, http.StatusTooManyRequests, w.Code, tc.method+" "+tc.path)
		require.JSONEq(t, limited, w.Body.String())
		if tc.status == http.StatusOK {
			require.Equal(t, "300", w.Header().Get("Retry-After"), tc.method+" "+tc.path)
		}
	}
}

func TestSCIMRateLimitBoundsEveryUnauthenticatedRequest(t *testing.T) {
	api, _ := setupSCIMAPI(t, func(config *conf.GlobalConfiguration) {
		config.RateLimitScim = 1
	})
	defer func() { require.NoError(t, api.db.Close()) }()
	require.NoError(t, models.TruncateAll(api.db))

	type request struct{ path, authorization string }
	requests := []request{}
	for _, header := range []string{"", "Bearer", "Bearer ", "bearer scim_invalid", "Bearer scim a", "Basic scim_invalid", "Bearer\tscim_invalid", "Bearer  scim_invalid"} {
		requests = append(requests, request{"/scim/v2/Users", header})
	}
	for _, path := range []string{"/scim/v2//Users", "/scim/v2/./Users", "/scim/v2/Users/", "/scim/v2/ServiceProviderConfig/"} {
		requests = append(requests, request{path, "Bearer scim_invalid"})
	}

	for i, tc := range requests {
		ip := fmt.Sprintf("203.0.113.%d", 100+i)
		limited := false
		for range 31 {
			r := httptest.NewRequest(http.MethodGet, tc.path, nil)
			if tc.authorization != "" {
				r.Header.Set("Authorization", tc.authorization)
			}
			r.Header.Set(api.config.RateLimitHeader, ip)
			w := httptest.NewRecorder()
			api.handler.ServeHTTP(w, r)
			limited = limited || w.Code == http.StatusTooManyRequests
		}
		require.True(t, limited, "%q %q", tc.path, tc.authorization)
	}
}
