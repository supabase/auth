package scim

import (
	"net/http"
	"strings"

	"github.com/supabase/auth/internal/api/scim/core"
	"github.com/supabase/auth/internal/api/scim/protocol"
	"github.com/supabase/auth/internal/conf"
)

const BasePath = "/scim/v2"

type Server struct {
	config *core.ServiceProviderConfig
}

func NewServer(config *conf.GlobalConfiguration) *Server {
	return &Server{
		config: core.NewServiceProviderConfig(
			strings.TrimRight(config.API.ExternalURL, "/")+BasePath,
			[]core.AuthenticationScheme{core.OAuthBearerToken().AsPrimary()},
		),
	}
}

func (srv *Server) ServiceProviderConfig(w http.ResponseWriter, r *http.Request) error {
	return protocol.Send(w, http.StatusOK, srv.config)
}

func (srv *Server) ResourceTypes(w http.ResponseWriter, r *http.Request) error {
	if hasFilter(r) {
		return filterForbidden()
	}
	return protocol.Send(w, http.StatusOK, protocol.NewListResponse([]any{}))
}

func (srv *Server) Schemas(w http.ResponseWriter, r *http.Request) error {
	if hasFilter(r) {
		return filterForbidden()
	}
	return protocol.Send(w, http.StatusOK, protocol.NewListResponse([]any{}))
}

func (srv *Server) NotFound(w http.ResponseWriter, r *http.Request) error {
	return protocol.NewError(http.StatusNotFound, "", "Endpoint or resource does not exist")
}

func (srv *Server) MethodNotAllowed(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Allow", http.MethodGet)
	return protocol.NewError(http.StatusMethodNotAllowed, "", "The request method is not supported by this endpoint")
}

func hasFilter(r *http.Request) bool {
	return r.URL.Query().Get("filter") != ""
}

func filterForbidden() error {
	return protocol.NewError(http.StatusForbidden, "", "Filtering is not supported on this endpoint")
}
