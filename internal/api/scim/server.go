package scim

import (
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase/auth/internal/storage"
)

const BasePath = "/scim/v2"

type Server struct {
	db                    *storage.Connection
	Users                 *ResourceServer[*core.User]
	serviceProviderConfig *core.ServiceProviderConfig
	resourceTypes         []*core.ResourceType
	schemas               []*core.Schema
}

func NewServer(db *storage.Connection, externalURL string) *Server {
	baseURL := Join(externalURL, BasePath)
	userSchema := newUserSchema(baseURL)

	return &Server{
		db:    db,
		Users: newUserResourceServer(db, baseURL, userSchema, protocol.DefaultLimits),
		serviceProviderConfig: newServiceProviderConfig(
			baseURL,
			core.NewOAuthBearerToken().AsPrimary(),
		).Sorting().Filtering(protocol.DefaultLimits.MaxCount),
		resourceTypes: []*core.ResourceType{newUserResourceType(baseURL, userSchema)},
		schemas:       []*core.Schema{userSchema},
	}
}

func newUserResourceServer(db *storage.Connection, baseURL string, schema *core.Schema, limits protocol.Limits) *ResourceServer[*core.User] {
	return NewResourceServer(
		limits,
		NewUserService(&userRepository{db: db, baseURL: baseURL, schema: schema}),
		ResourceSpec[*core.User]{
			Path:     "/Users",
			Schema:   schema,
			New:      func() *core.User { return new(core.User) },
			Validate: validateUser,
			Location: func(u *core.User) string { return u.Meta.Location },
		},
	)
}

func Join(base, segment string) string {
	return strings.TrimSuffix(base, "/") + "/" + strings.TrimPrefix(segment, "/")
}

func validateUser(user *core.User) *protocol.Error {
	if user.UserName == "" {
		return protocol.ErrInvalidValue(`"userName" is required`)
	}
	if !slices.Contains(user.Schemas, core.SchemaUser) {
		return protocol.ErrInvalidValue(`"schemas" must include the User schema URN`)
	}
	return nil
}

func (srv *Server) ServiceProviderConfig(w http.ResponseWriter, r *http.Request) error {
	return protocol.Send(w, http.StatusOK, srv.serviceProviderConfig)
}

func (srv *Server) ResourceTypes(w http.ResponseWriter, r *http.Request) error {
	return srv.list(w, r, srv.resourceTypes)
}

func (srv *Server) ResourceTypeByID(w http.ResponseWriter, r *http.Request) error {
	return srv.byID(w, r, srv.resourceTypes)
}

func (srv *Server) Schemas(w http.ResponseWriter, r *http.Request) error {
	return srv.list(w, r, srv.schemas)
}

func (srv *Server) SchemaByID(w http.ResponseWriter, r *http.Request) error {
	return srv.byID(w, r, srv.schemas)
}

func (srv *Server) NotFound(w http.ResponseWriter, r *http.Request) error {
	return NotFound(w, r)
}

func (srv *Server) list[T any](w http.ResponseWriter, r *http.Request, resources []T) error {
	if rejected, err := rejectFilter(w, r, protocol.ErrForbidden("Filtering is not supported on this endpoint")); rejected {
		return err
	}

	return protocol.Send(w, http.StatusOK, protocol.NewListResponse(1, len(resources), resources))
}

func (srv *Server) byID[T core.Resource](w http.ResponseWriter, r *http.Request, resources []T) error {
	id := urlParam(r, "id")

	for _, resource := range resources {
		if resource.ResourceID() == id {
			return protocol.Send(w, http.StatusOK, resource)
		}
	}
	return NotFound(w, r)
}

func urlParam(r *http.Request, key string) string {
	value := chi.URLParam(r, key)

	if decoded, err := url.PathUnescape(value); err == nil {
		return decoded
	}
	return value
}
