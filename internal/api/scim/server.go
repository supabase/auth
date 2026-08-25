package scim

import (
	"net/http"
	"net/url"

	"github.com/go-chi/chi/v5"
	"github.com/supabase/auth/internal/api/scim/core"
	"github.com/supabase/auth/internal/api/scim/protocol"
)

const BasePath = "/scim/v2"

type Server struct {
	serviceProviderConfig *core.ServiceProviderConfig
	resourceTypes         []*core.ResourceType
	schemas               []*core.Schema
}

func NewServer(externalURL string) *Server {
	baseURL := core.Join(externalURL, BasePath)
	userSchema := newUserSchema(baseURL)

	return &Server{
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
	return byID(w, r, srv.resourceTypes)
}

func (srv *Server) Schemas(w http.ResponseWriter, r *http.Request) error {
	return list(w, r, srv.schemas)
}

func (srv *Server) SchemaByID(w http.ResponseWriter, r *http.Request) error {
	return byID(w, r, srv.schemas)
}

func (srv *Server) NotFound(w http.ResponseWriter, r *http.Request) error {
	return notFound(w)
}

func list[T any](w http.ResponseWriter, r *http.Request, resources []T) error {
	if rejected, err := rejectFilter(w, r, protocol.ErrForbidden("Filtering is not supported on this endpoint")); rejected {
		return err
	}

	return protocol.Send(w, http.StatusOK, protocol.NewListResponse(1, len(resources), resources))
}

func byID[T core.Resource](w http.ResponseWriter, r *http.Request, resources []T) error {
	id := urlParam(r, "id")

	for _, resource := range resources {
		if resource.ResourceID() == id {
			return protocol.Send(w, http.StatusOK, resource)
		}
	}
	return notFound(w)
}

func notFound(w http.ResponseWriter) error {
	return protocol.WriteError(w, protocol.ErrNotFound("Endpoint or resource does not exist"))
}

func rejectFilter(w http.ResponseWriter, r *http.Request, unsupported *protocol.Error) (bool, error) {
	if !r.URL.Query().Has("filter") {
		return false, nil
	}
	return true, protocol.WriteError(w, unsupported)
}

func newUserSchema(baseURL string) *core.Schema {
	return core.
		NewSchema(baseURL, core.KindUser).
		Describe("User Account").
		With(
			core.NewAttribute("userName", core.TypeString, "Unique identifier for the User").
				AsRequired().
				UniqueOn(core.UniquenessServer),

			core.NewAttribute("name", core.TypeComplex,
				"The components of the user's name.").
				With(
					core.NewAttribute("formatted", core.TypeString, "The name formatted for display."),
					core.NewAttribute("familyName", core.TypeString, "The family name of the User."),
					core.NewAttribute("givenName", core.TypeString, "The given name of the User."),
					core.NewAttribute("middleName", core.TypeString, "The middle name(s) of the User."),
				),

			core.NewAttribute("emails", core.TypeComplex, "Email addresses for the user.").
				AsMultiValued().
				With(
					core.NewAttribute("value", core.TypeString, "An email address for the user."),
					core.NewAttribute("primary", core.TypeBoolean, "The 'primary' email address"),
				),

			core.NewAttribute("active", core.TypeBoolean, ""),
		)
}

func urlParam(r *http.Request, key string) string {
	value := chi.URLParam(r, key)

	if decoded, err := url.PathUnescape(value); err == nil {
		return decoded
	}
	return value
}
