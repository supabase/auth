package scim

import (
	"net/http"

	"github.com/supabase/auth/internal/api/scim/protocol"
	"github.com/supabase/auth/internal/conf"
)

const BasePath = "/scim/v2"

type Server struct {
	config *conf.GlobalConfiguration
}

func NewServer(config *conf.GlobalConfiguration) *Server {
	return &Server{
		config: config,
	}
}

func (srv *Server) ServiceProviderConfig(w http.ResponseWriter, r *http.Request) error {
	return srv.notImplemented(w)
}

func (srv *Server) ResourceTypes(w http.ResponseWriter, r *http.Request) error {
	return srv.notImplemented(w)
}

func (srv *Server) Schemas(w http.ResponseWriter, r *http.Request) error {
	return srv.notImplemented(w)
}

func (srv *Server) NotFound(w http.ResponseWriter, r *http.Request) error {
	return protocol.SendError(w, http.StatusNotFound, "", "Endpoint or resource does not exist")
}

func (srv *Server) notImplemented(w http.ResponseWriter) error {
	return protocol.SendError(w, http.StatusNotImplemented, "", "The request endpoint is not implemented")
}
