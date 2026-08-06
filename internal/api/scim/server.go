package scim

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/supabase/auth/internal/api/scim/core"
	"github.com/supabase/auth/internal/api/scim/protocol"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/observability"
	"github.com/supabase/auth/internal/storage"
)

const BasePath = "/scim/v2"

type Server struct {
	db                    *storage.Connection
	users                 Mapper[*models.User, *core.User]
	serviceProviderConfig *core.ServiceProviderConfig
	resourceTypes         []*core.ResourceType
	schemas               []*core.Schema
}

func NewServer(config *conf.GlobalConfiguration, db *storage.Connection) *Server {
	baseURL := strings.TrimRight(config.API.ExternalURL, "/") + BasePath
	userSchema := newUserSchema(baseURL)

	return &Server{
		db:    db,
		users: NewUserMapper(baseURL),
		serviceProviderConfig: core.NewServiceProviderConfig(
			baseURL,
			core.NewOAuthBearerToken().AsPrimary(),
		),
		resourceTypes: []*core.ResourceType{core.NewResourceType(baseURL, userSchema, core.EndpointUsers)},
		schemas:       []*core.Schema{userSchema},
	}
}

func (srv *Server) ServiceProviderConfig(w http.ResponseWriter, r *http.Request) error {
	return protocol.Send(w, http.StatusOK, srv.serviceProviderConfig)
}

func (srv *Server) ResourceTypes(w http.ResponseWriter, r *http.Request) error {
	return list(w, r, srv.resourceTypes)
}

func (srv *Server) ResourceTypeByID(w http.ResponseWriter, r *http.Request) error {
	id := urlParam(r, "id")

	for _, resourceType := range srv.resourceTypes {
		if resourceType.ID == core.ResourceTypeName(id) {
			return protocol.Send(w, http.StatusOK, resourceType)
		}
	}
	return srv.NotFound(w, r)
}

func (srv *Server) Schemas(w http.ResponseWriter, r *http.Request) error {
	return list(w, r, srv.schemas)
}

func (srv *Server) SchemaByID(w http.ResponseWriter, r *http.Request) error {
	id := urlParam(r, "id")

	for _, schema := range srv.schemas {
		if schema.ID == core.SchemaURI(id) {
			return protocol.Send(w, http.StatusOK, schema)
		}
	}
	return srv.NotFound(w, r)
}

// urlParam is chi.URLParam with the percent-encoding undone. chi matches
// against the raw path when one is present, so a client that encodes the
// colons of a schema URN gets back the encoded segment.
func urlParam(r *http.Request, key string) string {
	value := chi.URLParam(r, key)

	if decoded, err := url.PathUnescape(value); err == nil {
		return decoded
	}
	return value
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
