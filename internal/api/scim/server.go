package scim

import (
	"net/http"
	"strings"

	"github.com/supabase/auth/internal/api/scim/core"
	"github.com/supabase/auth/internal/api/scim/protocol"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/observability"
	"github.com/supabase/auth/internal/storage"
)

const BasePath = "/scim/v2"

type TokenExtractor func(r *http.Request) (string, error)

type Server struct {
	db                    *storage.Connection
	extract               TokenExtractor
	users                 Mapper[models.ProvisionedUser, *core.User]
	serviceProviderConfig *core.ServiceProviderConfig
}

func NewServer(config *conf.GlobalConfiguration, db *storage.Connection, extract TokenExtractor) *Server {
	baseURL := strings.TrimRight(config.API.ExternalURL, "/") + BasePath

	return &Server{
		db:      db,
		extract: extract,
		users:   NewUserMapper(baseURL),
		serviceProviderConfig: core.NewServiceProviderConfig(
			baseURL,
			core.NewOAuthBearerToken().AsPrimary(),
		),
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
	return protocol.SendError(w, http.StatusNotFound, "", "Endpoint or resource does not exist")
}

func (srv *Server) internalError(w http.ResponseWriter, r *http.Request, err error) error {
	observability.LogEntrySetField(r, "error", err.Error())
	return protocol.SendError(w, http.StatusInternalServerError, "", "Internal server error")
}

func list[T any](w http.ResponseWriter, r *http.Request, resources []T) error {
	if r.URL.Query().Get("filter") != "" {
		return protocol.SendError(w, http.StatusForbidden, "", "Filtering is not supported on this endpoint")
	}
	return protocol.Send(w, http.StatusOK, protocol.NewListResponse(resources))
}
