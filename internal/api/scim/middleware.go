package scim

import (
	"context"
	"net/http"

	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/api/shared"
	"github.com/supabase/auth/internal/models"
)

// TEMPORARY: this header stands in for the per-provider SCIM token
const ProviderHeaderName = "x-scim-provider-id"

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

	id := providerID(r)
	if id == uuid.Nil {
		_ = srv.NotFound(w, r)
		return nil, false
	}

	provider, err := models.FindSSOProviderByID(srv.db.WithContext(ctx), id)
	if err != nil {
		if models.IsNotFoundError(err) {
			_ = srv.NotFound(w, r)
			return nil, false
		}
		_ = srv.internalError(w, r, err)
		return nil, false
	}

	return shared.WithSSOProvider(ctx, provider), true
}

func providerID(r *http.Request) uuid.UUID {
	// TEMPORARY: reads the provider id from the "x-scim-provider-id" header until SCIM Tokens ship
	id, err := uuid.FromString(r.Header.Get(ProviderHeaderName))
	if err != nil {
		return uuid.Nil
	}

	return id
}
