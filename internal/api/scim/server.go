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

const BasePath = "/scim/v2"

func BaseURL(config *conf.GlobalConfiguration) string {
	return strings.TrimRight(config.API.ExternalURL, "/") + BasePath
}

func NewServer(config *conf.GlobalConfiguration, db *storage.Connection) http.Handler {
	locations := map[string]string{"User": BaseURL(config) + "/Users", "Group": BaseURL(config) + "/Groups"}
	return server.New(BasePath,
		core.NewServiceProviderConfig().Filtering(protocol.DefaultLimits.MaxCount).Patching().Sorting(),
		server.WithBaseURL(BaseURL(config)),
		server.ErrorHandler(func(r *http.Request, err error) {
			observability.GetLogEntry(r).Entry.WithError(err).Error("scim: request failed")
		}),
		server.WithResource(server.
			NewResource[*core.User]("User", "/Users", core.SchemaUser, core.UserAttributes()...).
			WithExtension(core.SchemaEnterpriseUser, core.EnterpriseUserAttributes()...).
			WithRepository(NewRepository[*core.User](db, "User", locations, core.Schemas{
				core.NewSchema(core.SchemaUser).With(core.UserAttributes()...),
				core.NewSchema(core.SchemaEnterpriseUser).With(core.EnterpriseUserAttributes()...),
			}, query.Derived("groups", "Group", "members"))),
		),
		server.WithResource(server.
			NewResource[*core.Group]("Group", "/Groups", core.SchemaGroup, core.GroupAttributes()...).
			WithRepository(NewRepository[*core.Group](db, "Group", locations, core.Schemas{
				core.NewSchema(core.SchemaGroup).With(core.GroupAttributes()...),
			}, query.Stored("members", "User", "Group"))),
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
