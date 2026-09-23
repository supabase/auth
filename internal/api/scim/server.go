package scim

import (
	"net/http"
	"strings"

	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase/auth/internal/conf"
)

const BasePath = "/scim/v2"

type Server struct {
	serviceProviderConfig *core.ServiceProviderConfig
}

func NewServer(config *conf.GlobalConfiguration) *Server {
	serviceProviderConfig := core.NewServiceProviderConfig().Authentication(core.NewOAuthBearerToken().AsPrimary())
	serviceProviderConfig.Meta.Location = strings.TrimRight(config.API.ExternalURL, "/") + BasePath + "/ServiceProviderConfig"
	return &Server{
		serviceProviderConfig: serviceProviderConfig,
	}
}

func (srv *Server) ServiceProviderConfig(w http.ResponseWriter, r *http.Request) error {
	return protocol.Send(w, http.StatusOK, srv.serviceProviderConfig)
}

func (srv *Server) ResourceTypes(w http.ResponseWriter, r *http.Request) error {
	return list(w, r, []any{})
}

func (srv *Server) Schemas(w http.ResponseWriter, r *http.Request) error {
	return list(w, r, []any{})
}

func (srv *Server) NotFound(w http.ResponseWriter, r *http.Request) error {
	return protocol.SendError(w, scimerrors.ErrNotFound("Endpoint or resource does not exist"))
}

func list[T any](w http.ResponseWriter, r *http.Request, resources []T) error {
	if r.URL.Query().Has("filter") {
		return protocol.SendError(w, scimerrors.ErrForbidden("Filtering is not supported on this endpoint"))
	}
	return protocol.Send(w, http.StatusOK, protocol.NewListResponse(1, len(resources), resources))
}
