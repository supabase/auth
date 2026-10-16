package scim

import (
	"context"
	"net/http"
	"strings"
	"uuid"

	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase-community/scim-go/pkg/server"
	"github.com/supabase/auth/internal/api/scim/store"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/ctxkey"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/observability"
	"github.com/supabase/auth/internal/storage"
)

var tokenKey = ctxkey.New[*models.SCIMToken]("scim_token")

const (
	BasePath   = "/scim/v2"
	usersPath  = "/Users"
	groupsPath = "/Groups"
	userType   = "User"
	groupType  = "Group"
)

func BaseURL(config *conf.GlobalConfiguration) string {
	return strings.TrimRight(config.API.ExternalURL, "/") + BasePath
}

func NewServer(config *conf.GlobalConfiguration, db *storage.Connection) http.Handler {
	resources := store.New(db, provider)
	base := BaseURL(config)
	errorHandler := func(r *http.Request, err error) {
		observability.GetLogEntry(r).Entry.WithError(err).Error("scim: request failed")
	}

	cfg := core.NewServiceProviderConfig().Filtering(protocol.DefaultLimits.MaxCount).Patching().Sorting().Versioning()
	return server.New(BasePath, cfg,
		server.ErrorHandler(errorHandler),
		server.WithBaseURL(base),
		server.WithResource(
			server.NewResource[*core.User](userType, usersPath, core.SchemaUser, core.UserAttributes()...).
				WithExtension(core.SchemaEnterpriseUser, core.EnterpriseUserAttributes()...).
				WithRepositoryFunc(repositoryFunc[*core.User](resources)),
		),
		server.WithResource(
			server.NewResource[*core.Group](groupType, groupsPath, core.SchemaGroup, core.GroupAttributes()...).
				WithRepositoryFunc(repositoryFunc[*core.Group](resources)),
		),
		server.WithAuthentication(core.NewOAuthBearerToken().AsPrimary(), authenticate(db)),
	)
}

func SendTooManyRequests(w http.ResponseWriter) error {
	return protocol.SendError(w, scimerrors.NewError(http.StatusTooManyRequests, "", "Request rate limit reached"))
}

func repositoryFunc[T core.Resource](db *store.DB) func(*server.Resource[T]) server.Repository[T] {
	return func(r *server.Resource[T]) server.Repository[T] {
		return server.NewRepository[T](db.Store(r.Schemas(), r.Location()), r.Schemas())
	}
}

func provider(ctx context.Context) (uuid.UUID, error) {
	token := tokenKey.Value(ctx)
	if token == nil {
		return uuid.UUID{}, scimerrors.ErrInternal("missing SCIM token")
	}
	return token.SSOProviderID, nil
}

func authenticate(db *storage.Connection) func(http.Handler) http.Handler {
	return server.RequireBearerToken(func(ctx context.Context, candidate string) (context.Context, error) {
		token, err := models.AuthenticateSCIMToken(db.WithContext(ctx), candidate)
		if models.IsNotFoundError(err) {
			return ctx, server.ErrInvalidToken
		}
		if err != nil {
			return ctx, err
		}
		return tokenKey.WithValue(ctx, token), nil
	})
}
