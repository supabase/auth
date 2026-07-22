package scim

import (
	"net/http"
)

const mediaType = "application/scim+json"

type Server struct {
}

func NewServer() *Server {
	return &Server{}
}

func (srv *Server) ServiceProviderConfig(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", mediaType)
	w.WriteHeader(http.StatusOK)
	return ToJSON(w, &ServiceProviderConfiguration{
		Schemas:          []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		DocumentationURI: "https://supabase.com/docs/guides/auth/enterprise-sso/scim",
	})
}

func (srv *Server) ResourceTypes(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", mediaType)
	w.WriteHeader(http.StatusNotImplemented)
	return nil
}

func (srv *Server) Schemas(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", mediaType)
	w.WriteHeader(http.StatusNotImplemented)
	return nil
}
