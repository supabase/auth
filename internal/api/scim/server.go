package scim

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/api/scim/core"
	"github.com/supabase/auth/internal/api/scim/protocol"
	"github.com/supabase/auth/internal/observability"
)

const BasePath = "/scim/v2"

// Config is what a SCIM server needs from the application hosting it. It holds
// collaborators rather than a database connection so that only the stores
// themselves can reach one.
type Config struct {
	// ExternalURL is the origin this server is reached at. BasePath is this
	// package's business to append.
	ExternalURL string

	// Limits bound pagination. A zero value means protocol.DefaultLimits:
	// Section 3.4.2.4 leaves the maximum to the provider, and a maximum of
	// none would serve nothing.
	Limits protocol.Limits

	Users   Store[*core.User]
	Tenants Tenants
}

type Server struct {
	limits                protocol.Limits
	users                 Store[*core.User]
	tenants               Tenants
	serviceProviderConfig *core.ServiceProviderConfig
	resourceTypes         []*core.ResourceType
	schemas               []*core.Schema
}

func NewServer(cfg Config) *Server {
	baseURL := core.Join(cfg.ExternalURL, BasePath)
	userSchema := newUserSchema(baseURL)

	limits := cfg.Limits
	if limits == (protocol.Limits{}) {
		limits = protocol.DefaultLimits
	}

	return &Server{
		limits:  limits,
		users:   cfg.Users,
		tenants: cfg.Tenants,
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

	if rejected, err := rejectFilter(w, r, protocol.ErrInvalidFilter(filterUnsupported)); rejected {
		return err
	}

	query, err := srv.limits.ParseSearchRequest(r.URL.Query())
	if err != nil {
		return protocol.WriteError(w, err)
	}

	users, ok := srv.tenantUsers(r)
	if !ok {
		return srv.NotFound(w, r)
	}

	items, total, err := users.List(ctx, query)
	if err != nil {
		return srv.storeError(w, r, err)
	}

	return protocol.Send(w, http.StatusOK, protocol.NewListResponse(query.StartIndex, total, items))
}

func (srv *Server) UserByID(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	id, err := uuid.FromString(urlParam(r, "id"))
	if err != nil {
		return srv.NotFound(w, r)
	}

	users, ok := srv.tenantUsers(r)
	if !ok {
		return srv.NotFound(w, r)
	}

	user, err := users.Get(ctx, id.String())
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return srv.NotFound(w, r)
		}
		return srv.internalError(w, r, err)
	}

	return protocol.Send(w, http.StatusOK, user)
}

// tenantUsers is the requesting tenant's collection of Users. Every handler
// scopes through here, so the tenant is named once for a request rather than
// once for each query it makes.
func (srv *Server) tenantUsers(r *http.Request) (Repository[*core.User], bool) {
	tenant, ok := tenantFrom(r.Context())
	if !ok {
		return nil, false
	}
	return srv.users.For(tenant), true
}

func (srv *Server) NotFound(w http.ResponseWriter, r *http.Request) error {
	return protocol.WriteError(w, protocol.ErrNotFound("Endpoint or resource does not exist"))
}

func list[T any](w http.ResponseWriter, r *http.Request, resources []T) error {
	if rejected, err := rejectFilter(w, r, protocol.ErrForbidden(filterUnsupported)); rejected {
		return err
	}

	return protocol.Send(w, http.StatusOK, protocol.NewListResponse(1, len(resources), resources))
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

// storeError answers an error from a repository. A *protocol.Error describes
// something the client asked for and is reported as it stands; anything else is
// this server's problem and is not disclosed.
func (srv *Server) storeError(w http.ResponseWriter, r *http.Request, err error) error {
	var scimErr *protocol.Error
	if errors.As(err, &scimErr) {
		return protocol.WriteError(w, scimErr)
	}
	return srv.internalError(w, r, err)
}

func (srv *Server) internalError(w http.ResponseWriter, r *http.Request, err error) error {
	observability.LogEntrySetField(r, "error", err.Error())
	return protocol.WriteError(w, protocol.ErrInternal("Internal server error"))
}

// filterUnsupported is the detail this server gives for a filter it will not
// honour. The status differs by endpoint, so the caller supplies the error.
const filterUnsupported = "Filtering is not supported on this endpoint"

func rejectFilter(w http.ResponseWriter, r *http.Request, unsupported *protocol.Error) (bool, error) {
	if !r.URL.Query().Has("filter") {
		return false, nil
	}
	return true, protocol.WriteError(w, unsupported)
}
