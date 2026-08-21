package scim

import (
	"context"
	"errors"
	"net/http"
)

// TEMPORARY: this header stands in for the per-provider SCIM token
const ProviderHeaderName = "x-scim-provider-id"

type tenantKey struct{}

// withTenant carries the tenant across the one hop a context is for: from the
// middleware that resolved it to the handler that serves the request. The
// storage interfaces take the tenant explicitly, so no query can omit it.
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
			_ = srv.NotFound(w, r)
		} else {
			_ = srv.internalError(w, r, err)
		}
		return nil, false
	}

	return withTenant(ctx, tenant), true
}

// credential is what a request offers as proof of the tenant it may act for.
//
// TEMPORARY: a provider id in a header until SCIM tokens ship, when this reads
// the bearer token out of Authorization instead.
func credential(r *http.Request) string {
	return r.Header.Get(ProviderHeaderName)
}
