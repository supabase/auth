package scim

import (
	"context"

	"github.com/gofrs/uuid"
	"github.com/supabase-community/scim-go/pkg/server"
	"github.com/supabase/auth/internal/ctxkey"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

var ssoProviderIDKey = ctxkey.New[uuid.UUID]("scim_sso_provider_id")

func SSOProviderID(ctx context.Context) (uuid.UUID, bool) {
	return ssoProviderIDKey.Lookup(ctx)
}

func NewTokenValidator(db *storage.Connection) server.TokenValidator {
	return func(ctx context.Context, candidate string) (context.Context, error) {
		token, err := models.AuthenticateSCIMToken(db.WithContext(ctx), candidate)
		if models.IsNotFoundError(err) {
			return ctx, server.ErrInvalidToken
		}
		if err != nil {
			return ctx, err
		}
		return ssoProviderIDKey.WithValue(ctx, token.SSOProviderID), nil
	}
}
