package scim

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/api/scim/core"
	"github.com/supabase/auth/internal/api/scim/protocol"
	"github.com/supabase/auth/internal/api/shared"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/observability"
	"github.com/supabase/auth/internal/storage"
)

const BasePath = "/scim/v2"

type Server struct {
	db                    *storage.Connection
	users                 UserRepository
	serviceProviderConfig *core.ServiceProviderConfig
	resourceTypes         []*core.ResourceType
	schemas               []*core.Schema
}

func NewServer(config *conf.GlobalConfiguration, db *storage.Connection) *Server {
	baseURL := core.Join(config.API.ExternalURL, BasePath)
	userSchema := newUserSchema(baseURL)

	return &Server{
		db:    db,
		users: NewUserRepository(db),
		serviceProviderConfig: core.NewServiceProviderConfig(
			baseURL,
			core.NewOAuthBearerToken().AsPrimary(),
		),
		resourceTypes: []*core.ResourceType{core.NewResourceType(baseURL, core.KindUser, userSchema)},
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
	return byID(srv, w, r, srv.resourceTypes)
}

func (srv *Server) Schemas(w http.ResponseWriter, r *http.Request) error {
	return list(w, r, srv.schemas)
}

func (srv *Server) SchemaByID(w http.ResponseWriter, r *http.Request) error {
	return byID(srv, w, r, srv.schemas)
}

func (srv *Server) Users(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	if rejected, err := rejectFilter(w, r, http.StatusBadRequest, protocol.ScimTypeInvalidFilter); rejected {
		return err
	}

	page, err := protocol.ParsePage(r.URL.Query())
	if err != nil {
		return protocol.SendError(w, http.StatusBadRequest, protocol.ScimTypeInvalidValue, err.Error())
	}

	provider := shared.GetSSOProvider(ctx)
	if provider == nil {
		return srv.NotFound(w, r)
	}

	users, total, err := srv.users.List(ctx, provider.ID.String(), page.Count, page.Offset())
	if err != nil {
		return srv.internalError(w, r, err)
	}

	return protocol.Send(w, http.StatusOK, protocol.NewPage(users, page.StartIndex, total))
}

func (srv *Server) UserByID(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	id, err := uuid.FromString(urlParam(r, "id"))
	if err != nil {
		return srv.NotFound(w, r)
	}

	provider := shared.GetSSOProvider(ctx)
	if provider == nil {
		return srv.NotFound(w, r)
	}

	user, err := srv.users.Get(ctx, provider.ID.String(), id.String())
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return srv.NotFound(w, r)
		}
		return srv.internalError(w, r, err)
	}

	return protocol.Send(w, http.StatusOK, user)
}

func (srv *Server) NotFound(w http.ResponseWriter, r *http.Request) error {
	return protocol.SendError(w, http.StatusNotFound, "", "Endpoint or resource does not exist")
}

func list[T any](w http.ResponseWriter, r *http.Request, resources []T) error {
	if r.URL.Query().Has("filter") {
		return protocol.SendError(w, http.StatusForbidden, "", "Filtering is not supported on this endpoint")
	}

	return protocol.Send(w, http.StatusOK, protocol.NewListResponse(resources))
}

func byID[T core.Resource](srv *Server, w http.ResponseWriter, r *http.Request, resources []T) error {
	id := urlParam(r, "id")

	for _, resource := range resources {
		if resource.ResourceID() == id {
			return protocol.Send(w, http.StatusOK, resource)
		}
	}
	return srv.NotFound(w, r)
}

func newUserSchema(baseURL string) *core.Schema {
	return core.
		NewSchema(baseURL, core.KindUser).
		Describe("User Account").
		With(
			core.NewAttribute("userName", core.TypeString, "Unique identifier for the User.").
				AsRequired().
				UniqueOn(core.UniquenessServer),
		)
}

func urlParam(r *http.Request, key string) string {
	value := chi.URLParam(r, key)

	if decoded, err := url.PathUnescape(value); err == nil {
		return decoded
	}
	return value
}

func (srv *Server) internalError(w http.ResponseWriter, r *http.Request, err error) error {
	observability.LogEntrySetField(r, "error", err.Error())
	return protocol.SendError(w, http.StatusInternalServerError, "", "Internal server error")
}

func rejectFilter(w http.ResponseWriter, r *http.Request, status int, scimType protocol.ScimType) (bool, error) {
	if !r.URL.Query().Has("filter") {
		return false, nil
	}
	return true, protocol.SendError(w, status, scimType, "Filtering is not supported on this endpoint")
}
