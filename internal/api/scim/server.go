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

const BasePath = "/scim/v2"

type Server struct {
	server *server.Server
}

func NewServer(config *conf.GlobalConfiguration) *Server {
	serviceProviderConfig := core.NewServiceProviderConfig(BasePath).
		Sorting().
		Filtering(protocol.DefaultLimits.MaxCount).
		Patching().
		Versioning().
		Authentication(core.NewOAuthBearerToken().AsPrimary())
	serviceProviderConfig.Meta.Location = strings.TrimRight(config.API.ExternalURL, "/") + BasePath + "/ServiceProviderConfig"

	return &Server{
		server: server.New(serviceProviderConfig,
			server.ErrorHandler(logError),
			server.WithResource(server.NewResource[*core.User]("User", "/Users", core.SchemaUser, userFields())),
		),
	}
}

func (srv *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	srv.server.ServeHTTP(w, r)
}

func (srv *Server) NotFound(w http.ResponseWriter, r *http.Request) error {
	return protocol.SendError(w, scimerrors.ErrNotFound("Endpoint or resource does not exist"))
}

func logError(r *http.Request, err error) {
	observability.GetLogEntry(r).Entry.WithError(err).Error("scim: unable to send response")
}
