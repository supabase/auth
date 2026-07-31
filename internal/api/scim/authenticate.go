package scim

import (
	"context"
	"net/http"
	"strings"

	"github.com/supabase/auth/internal/api/scim/protocol"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/observability"
)

var providerKey = NewKey[*models.SSOProvider]("sso_provider")

func (srv *Server) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, ok := srv.authenticate(w, r)
		if !ok {
			return
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (srv *Server) authenticate(w http.ResponseWriter, r *http.Request) (context.Context, bool) {
	ctx := r.Context()

	token, ok := parseBearerToken(r.Header.Get("Authorization"))
	if !ok {
		unauthorized(w)
		return nil, false
	}

	provider, err := models.FindSSOProviderBySCIMToken(srv.db.WithContext(ctx), token)
	if err != nil {
		if models.IsNotFoundError(err) {
			unauthorized(w)
			return nil, false
		}
		srv.internalError(w, r, err)
		return nil, false
	}

	if !provider.IsEnabled() {
		protocol.SendError(w, http.StatusForbidden, "", "SCIM is not available for this provider")
		return nil, false
	}

	observability.LogEntrySetField(r, "sso_provider_id", provider.ID.String())

	return providerKey.With(ctx, provider), true
}

func parseBearerToken(header string) (string, bool) {
	scheme, rest, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}

	token := strings.TrimSpace(rest)
	if token == "" || strings.ContainsAny(token, " \t\r\n\v\f") {
		return "", false
	}

	return token, true
}

func unauthorized(w http.ResponseWriter) error {
	w.Header().Set("WWW-Authenticate", "Bearer")
	return protocol.SendError(w, http.StatusUnauthorized, "", "A valid SCIM bearer token is required")
}
