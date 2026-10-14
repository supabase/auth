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
	return server.New(BasePath,
		core.NewServiceProviderConfig().Filtering(protocol.DefaultLimits.MaxCount).Patching().Sorting(),
		server.WithBaseURL(base),
		server.ErrorHandler(func(r *http.Request, err error) {
			observability.GetLogEntry(r).Entry.WithError(err).Error("scim: request failed")
		}),
		server.WithResource(newResource[*core.User](db, userType, usersPath, locations, inverses, core.Schemas{
			core.NewSchema(core.SchemaUser).With(core.UserAttributes()...),
			core.NewSchema(core.SchemaEnterpriseUser).With(core.EnterpriseUserAttributes()...),
		})),
		server.WithResource(newResource[*core.Group](db, groupType, groupsPath, locations, inverses, core.Schemas{
			core.NewSchema(core.SchemaGroup).With(core.GroupAttributes()...),
		})),
		server.WithAuthentication(core.NewOAuthBearerToken().AsPrimary(), authenticate(db)),
	)
}

func SendTooManyRequests(w http.ResponseWriter) error {
	return protocol.SendError(w, scimerrors.NewError(http.StatusTooManyRequests, "", "Request rate limit reached"))
}

func newResource[T core.Resource](db *storage.Connection, resourceType, path string, locations map[string]string, inverses map[query.Edge]query.Edge, schemas core.Schemas) *server.Resource[T] {
	repo := newRepository[T](db, resourceType, locations, schemas, inverses)
	resource := server.NewResource[T](resourceType, path, schemas.Base().ID, schemas.Base().Attributes...)
	for _, extension := range schemas.Extensions() {
		resource = resource.WithExtension(extension.ID, extension.Attributes...)
	}
	return resource.WithRepository(repo).WithService(repo.wrap)
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
