package scim

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/supabase/auth/internal/api/scim/protocol"
)

const bearerScheme = "bearer "

type tenantKey struct{}

type scimToken struct {
	ID            string `db:"id"`
	SSOProviderID string `db:"sso_provider_id"`
}

func withTenant(ctx context.Context, tenant string) context.Context {
	return context.WithValue(ctx, tenantKey{}, tenant)
}

func tenantFrom(ctx context.Context) (string, bool) {
	tenant, ok := ctx.Value(tenantKey{}).(string)
	return tenant, ok && tenant != ""
}

func (srv *Server) Tenant(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, ok := srv.tenant(w, r)
		if !ok {
			return
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (srv *Server) tenant(w http.ResponseWriter, r *http.Request) (context.Context, bool) {
	ctx := r.Context()

	tenant, err := srv.lookup(ctx, credential(r))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			_ = srv.unauthorized(w)
		} else {
			_ = srv.internalError(w, r, err)
		}
		return nil, false
	}

	return withTenant(ctx, tenant), true
}

// unauthorized answers a credential that names no tenant. RFC 7644,
// Section 3.12 gives 401 for a missing or invalid authorization header, and
// RFC 6750, Section 3 asks for the challenge that says which scheme would work.
func (srv *Server) unauthorized(w http.ResponseWriter) error {
	w.Header().Set("WWW-Authenticate", `Bearer realm="SCIM"`)
	return protocol.WriteError(w, protocol.ErrUnauthorized("Bearer token is missing or invalid"))
}

// credential is the bearer token a SCIM client authenticates with, per RFC 7644,
// Section 2 and RFC 6750, Section 2.1.
func credential(r *http.Request) string {
	header := r.Header.Get("Authorization")

	if len(header) < len(bearerScheme) || !strings.EqualFold(header[:len(bearerScheme)], bearerScheme) {
		return ""
	}
	return strings.TrimSpace(header[len(bearerScheme):])
}

func (srv *Server) lookup(ctx context.Context, credential string) (string, error) {
	if !strings.HasPrefix(credential, TokenPrefix) {
		return "", ErrNotFound
	}

	var rows []scimToken
	err := srv.db.WithContext(ctx).RawQuery(
		"SELECT t.id, t.sso_provider_id FROM scim_tokens t"+
			" JOIN sso_providers p ON p.id = t.sso_provider_id"+
			" WHERE t.token_hash = ?"+
			"   AND t.revoked_at IS NULL"+
			"   AND (t.expires_at IS NULL OR t.expires_at > now())"+
			"   AND (p.disabled IS NULL OR p.disabled = false)",
		hashToken(credential),
	).All(&rows)
	if err != nil {
		return "", fmt.Errorf("scim: looking up token: %w", err)
	}

	if len(rows) == 0 {
		return "", ErrNotFound
	}

	srv.touch(ctx, rows[0].ID)
	return rows[0].SSOProviderID, nil
}

func (srv *Server) touch(ctx context.Context, id string) {
	_ = srv.db.WithContext(ctx).RawQuery("UPDATE scim_tokens SET last_used_at = now() WHERE id = ?", id).Exec()
}
