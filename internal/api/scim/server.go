package scim

import (
	"context"
	"net/http"
	"strings"

	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase-community/scim-go/pkg/server"
	"github.com/supabase/auth/internal/api/scim/query"
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
	base := BaseURL(config)
	errorHandler := func(r *http.Request, err error) {
		observability.GetLogEntry(r).Entry.WithError(err).Error("scim: request failed")
	}

	cfg := core.NewServiceProviderConfig().Filtering(protocol.DefaultLimits.MaxCount).Patching().Sorting()
	return server.New(BasePath, cfg,
		server.ErrorHandler(errorHandler),
		server.WithBaseURL(base),
		server.WithResource(
			server.NewResource[*core.User](userType, usersPath, core.SchemaUser, core.UserAttributes()...).
				WithExtension(core.SchemaEnterpriseUser, core.EnterpriseUserAttributes()...).
				WithRepositoryFunc(func(r *server.Resource[*core.User]) server.Repository[*core.User] {
					return newRepository[*core.User](db, query.NewResource(
						userType,
						r.Schemas(),
						r.Location(),
						map[string]string{"groups": "members"},
					))
				}),
		),
		server.WithResource(
			server.NewResource[*core.Group](groupType, groupsPath, core.SchemaGroup, core.GroupAttributes()...).
				WithRepositoryFunc(func(r *server.Resource[*core.Group]) server.Repository[*core.Group] {
					return newRepository[*core.Group](db, query.NewResource(
						groupType,
						r.Schemas(),
						r.Location(),
						nil,
					))
				}),
		),
		server.WithAuthentication(core.NewOAuthBearerToken().AsPrimary(), authenticate(db)),
	)
}

func SendTooManyRequests(w http.ResponseWriter) error {
	return protocol.SendError(w, scimerrors.NewError(http.StatusTooManyRequests, "", "Request rate limit reached"))
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
