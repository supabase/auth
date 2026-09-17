package scim

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/supabase/auth/internal/api/shared"
	"github.com/supabase/auth/internal/models"
)

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

	tenant, err := srv.lookup(ctx, shared.Credential(r))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			_ = unauthorized(w)
		} else {
			_ = internalError(w, r, err)
		}
		return nil, false
	}

	return tenantKey.WithValue(ctx, tenant), true
}

func (srv *Server) lookup(ctx context.Context, bearerToken string) (*Tenant, error) {
	if !strings.HasPrefix(bearerToken, models.SCIMTokenPrefix) {
		return nil, ErrNotFound
	}

	provider, err := models.FindSSOProviderBySCIMToken(srv.db.WithContext(ctx), bearerToken)
	if err != nil {
		if errors.Is(err, models.SSOProviderNotFoundError{}) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scim: looking up token: %w", err)
	}

	return provider, nil
}
