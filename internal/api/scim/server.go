package scim

import (
	"net/http"
	"strings"

	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase-community/scim-go/pkg/server"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/observability"
)

const (
	BasePath         = "/scim/v2"
	DocumentationURI = "https://supabase.com/docs/guides/auth/enterprise-sso/scim"
)

type Server struct {
	server *server.Server
}

func NewServer(config *conf.GlobalConfiguration, validate server.TokenValidator, users server.Repository[*core.User]) *Server {
	serviceProviderConfig := core.NewServiceProviderConfig(BasePath).
		Filtering(protocol.DefaultLimits.MaxCount).
		Patching()
	serviceProviderConfig.DocumentationURI = DocumentationURI
	serviceProviderConfig.Meta.Location = BaseURL(config) + "/ServiceProviderConfig"

	return &Server{
		server: server.New(serviceProviderConfig,
			server.ErrorHandler(logError),
			server.WithResource(server.NewResource[*core.User]("User", "/Users", core.SchemaUser, userAttributes()...).WithRepository(users)),
			server.WithAuthentication(core.NewOAuthBearerToken().AsPrimary(), server.RequireBearerToken(validate)),
		),
	}
}

func BaseURL(config *conf.GlobalConfiguration) string {
	return strings.TrimRight(config.API.ExternalURL, "/") + BasePath
}

func (srv *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	srv.server.ServeHTTP(w, r)
}

func (srv *Server) NotFound(w http.ResponseWriter, r *http.Request) error {
	return protocol.SendError(w, scimerrors.ErrNotFound("Endpoint or resource does not exist"))
}

func (srv *Server) TooManyRequests(w http.ResponseWriter, r *http.Request) error {
	return protocol.SendError(w, scimerrors.NewError(http.StatusTooManyRequests, "", "Request rate limit reached"))
}

func logError(r *http.Request, err error) {
	observability.GetLogEntry(r).Entry.WithError(err).Error("scim: request failed")
}
