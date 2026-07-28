package scim

import (
	"context"
	"net/http"

	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/conf"
)

const mediaType = "application/scim+json"

type Server struct {
	config *conf.GlobalConfiguration
}

func NewServer(config *conf.GlobalConfiguration) *Server {
	return &Server{
		config: config,
	}
}

func (srv *Server) Middleware(w http.ResponseWriter, r *http.Request) (context.Context, error) {
	if !srv.config.Experimental.ScimEnabled {
		return nil, apierrors.NewNotFoundError(apierrors.ErrorCodeFeatureDisabled, "SCIM server is disabled")
	}
	return r.Context(), nil
}

func (srv *Server) ServiceProviderConfig(w http.ResponseWriter, r *http.Request) error {
	return srv.notImplemented(w, r)
}

func (srv *Server) ResourceTypes(w http.ResponseWriter, r *http.Request) error {
	return srv.notImplemented(w, r)
}

func (srv *Server) Schemas(w http.ResponseWriter, r *http.Request) error {
	return srv.notImplemented(w, r)
}

func (srv *Server) notImplemented(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", mediaType)
	w.WriteHeader(http.StatusNotImplemented)
	return nil
}
