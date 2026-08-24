package scim

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api/scim/protocol"
)

func TestCredential(t *testing.T) {
	for _, tc := range []struct{ name, header, expected string }{
		{"a bearer token", "Bearer scim_abc", "scim_abc"},
		{"a lowercase scheme, per RFC 7235", "bearer scim_abc", "scim_abc"},
		{"a mixed case scheme", "BeArEr scim_abc", "scim_abc"},
		{"surrounding whitespace", "Bearer   scim_abc  ", "scim_abc"},
		{"no header at all", "", ""},
		{"another scheme", "Basic dXNlcjpwYXNzd29yZA==", ""},
		{"the scheme with nothing after it", "Bearer ", ""},
		{"the scheme alone", "Bearer", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, BasePath+"/Users", nil)
			if tc.header != "" {
				r.Header.Set("Authorization", tc.header)
			}

			assert.Equal(t, tc.expected, credential(r))
		})
	}
}

func TestServerTenantMiddleware(t *testing.T) {
	db := newTestDB(t)
	provider := newTenant(t, db)
	token := grantToken(t, db, provider)

	srv := NewServer(Config{
		ExternalURL: testExternalURL,
		Users:       NewUserStore(db, testExternalURL),
		Tenants:     NewTokenTenants(db),
	})

	served := func(t *testing.T, authorization string) (*httptest.ResponseRecorder, string) {
		t.Helper()

		var seen string
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen, _ = tenantFrom(r.Context())
			w.WriteHeader(http.StatusTeapot)
		})

		r := httptest.NewRequest(http.MethodGet, BasePath+"/Users", nil)
		if authorization != "" {
			r.Header.Set("Authorization", authorization)
		}

		w := httptest.NewRecorder()
		srv.Tenant(next).ServeHTTP(w, r)
		return w, seen
	}

	t.Run("hands the tenant to the handler", func(t *testing.T) {
		w, seen := served(t, "Bearer "+token)

		assert.Equal(t, http.StatusTeapot, w.Code, "the handler ran")
		assert.Equal(t, provider, seen)
	})

	t.Run("answers 401 with a challenge when the token is unknown", func(t *testing.T) {
		unknown, _ := NewSCIMToken()

		w, seen := served(t, "Bearer "+unknown)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, `Bearer realm="SCIM"`, w.Header().Get("WWW-Authenticate"))
		assert.Equal(t, protocol.MediaType, w.Header().Get("Content-Type"))
		assert.Empty(t, seen, "the handler never ran")
	})

	t.Run("answers 401 when there is no Authorization header", func(t *testing.T) {
		w, seen := served(t, "")

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Empty(t, seen)
	})

	t.Run("says the same thing however the token failed", func(t *testing.T) {
		revoked := grantToken(t, db, provider)
		require.NoError(t, db.RawQuery(
			"UPDATE scim_tokens SET revoked_at = now() WHERE token_hash = ?", hashToken(revoked),
		).Exec())
		unknown, _ := NewSCIMToken()

		revokedResponse, _ := served(t, "Bearer "+revoked)
		unknownResponse, _ := served(t, "Bearer "+unknown)

		assert.Equal(t, unknownResponse.Code, revokedResponse.Code)
		assert.JSONEq(t, unknownResponse.Body.String(), revokedResponse.Body.String(),
			"which way a token failed is not something an unauthenticated caller is owed")
	})
}
