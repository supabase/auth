package scim

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/supabase/auth/internal/api/scim/protocol"
)

const bearerScheme = "bearer "

type tenantKey struct{}

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

	tenant, err := srv.tenants.Lookup(ctx, credential(r))
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
