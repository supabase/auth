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
	locations := map[string]string{userType: base + usersPath, groupType: base + groupsPath}
	inverses := map[query.Edge]query.Edge{{Type: userType, Attribute: "groups"}: {Type: groupType, Attribute: "members"}}
	users := newRepository[*core.User](db, userType, query.NewResource(userType, core.Schemas{
		core.NewSchema(core.SchemaUser).With(core.UserAttributes()...),
		core.NewSchema(core.SchemaEnterpriseUser).With(core.EnterpriseUserAttributes()...),
	}, locations, inverses))
	groups := newRepository[*core.Group](db, groupType, query.NewResource(groupType, core.Schemas{
		core.NewSchema(core.SchemaGroup).With(core.GroupAttributes()...),
	}, locations, inverses))
	return server.New(BasePath,
		core.NewServiceProviderConfig().Filtering(protocol.DefaultLimits.MaxCount).Patching().Sorting(),
		server.WithBaseURL(base),
		server.ErrorHandler(func(r *http.Request, err error) {
			observability.GetLogEntry(r).Entry.WithError(err).Error("scim: request failed")
		}),
		server.WithResource(server.NewResource[*core.User](userType, usersPath, core.SchemaUser, core.UserAttributes()...).
			WithExtension(core.SchemaEnterpriseUser, core.EnterpriseUserAttributes()...).
			WithRepository(users)),
		server.WithResource(server.NewResource[*core.Group](groupType, groupsPath, core.SchemaGroup, core.GroupAttributes()...).
			WithRepository(groups)),
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
