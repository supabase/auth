package scim

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase/auth/internal/api/shared"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/observability"
	"github.com/supabase/auth/internal/storage"
)

const BasePath = "/scim/v2"

type Server struct {
	db                    *storage.Connection
	limits                protocol.Limits
	users                 Repository[*core.User]
	serviceProviderConfig *core.ServiceProviderConfig
	resourceTypes         []*core.ResourceType
	schemas               []*core.Schema
}

func NewServer(db *storage.Connection, externalURL string) *Server {
	baseURL := Join(externalURL, BasePath)
	userSchema := newUserSchema(baseURL)

	return &Server{
		db:     db,
		limits: protocol.DefaultLimits,
		users:  &userRepository{db: db, baseURL: baseURL},
		serviceProviderConfig: newServiceProviderConfig(
			baseURL,
			core.NewOAuthBearerToken().AsPrimary(),
		).Sorting(),
		resourceTypes: []*core.ResourceType{newUserResourceType(baseURL, userSchema)},
		schemas:       []*core.Schema{userSchema},
	}
}

func Join(base, segment string) string {
	return strings.TrimSuffix(base, "/") + "/" + strings.TrimPrefix(segment, "/")
}

func newServiceProviderConfig(baseURL string, schemes ...*core.AuthenticationScheme) *core.ServiceProviderConfig {
	if schemes == nil {
		schemes = []*core.AuthenticationScheme{}
	}
	return &core.ServiceProviderConfig{
		Schemas:               []core.SchemaURI{core.SchemaServiceProviderConfig},
		AuthenticationSchemes: schemes,
		Meta: core.Meta{
			ResourceType: "ServiceProviderConfig",
			Location:     Join(baseURL, "/ServiceProviderConfig"),
		},
	}
}

func newUserResourceType(baseURL string, schema *core.Schema) *core.ResourceType {
	return &core.ResourceType{
		Schemas:     []core.SchemaURI{core.SchemaResourceType},
		ID:          "User",
		Name:        "User",
		Description: schema.Description,
		Endpoint:    "/Users",
		Schema:      schema.ID,
		Meta: core.Meta{
			ResourceType: "ResourceType",
			Location:     Join(Join(baseURL, "/ResourceTypes"), "User"),
		},
	}
}

func (srv *Server) Tenant(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, ok := srv.tenant(w, r)
		if !ok {
			return
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
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

func (srv *Server) Users(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	query, err := srv.limits.ParseSearchRequest(r.URL.Query())
	if err != nil {
		return protocol.SendError(w, err)
	}

	items, total, err := srv.users.List(ctx, query)
	if err != nil {
		return srv.sendError(w, r, err)
	}

	return protocol.Send(w, http.StatusOK, protocol.NewListResponse(query.StartIndex, total, items))
}

func (srv *Server) UserByID(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	id, err := uuid.FromString(urlParam(r, "id"))
	if err != nil {
		return srv.NotFound(w, r)
	}

	user, err := srv.users.Get(ctx, id.String())
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return srv.NotFound(w, r)
		}
		return srv.sendError(w, r, err)
	}

	return protocol.Send(w, http.StatusOK, user)
}

func (srv *Server) CreateUser(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	user, err := srv.decodeUser(r)
	if err != nil {
		return protocol.SendError(w, err)
	}
	if err := srv.validateUser(user); err != nil {
		return protocol.SendError(w, err)
	}

	created, err := srv.users.Create(ctx, user)
	if err != nil {
		return srv.sendError(w, r, err)
	}

	w.Header().Set("Location", created.Meta.Location)
	return protocol.Send(w, http.StatusCreated, created)
}

func (srv *Server) ReplaceUser(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	id, err := uuid.FromString(urlParam(r, "id"))
	if err != nil {
		return srv.NotFound(w, r)
	}

	user, err := srv.decodeUser(r)
	if err != nil {
		return protocol.SendError(w, err)
	}
	if err := srv.validateUser(user); err != nil {
		return protocol.SendError(w, err)
	}

	replaced, err := srv.users.Replace(ctx, id.String(), user)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return srv.NotFound(w, r)
		}
		return srv.sendError(w, r, err)
	}
	return protocol.Send(w, http.StatusOK, replaced)
}

func (srv *Server) DeleteUser(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	id, err := uuid.FromString(urlParam(r, "id"))
	if err != nil {
		return srv.NotFound(w, r)
	}

	if err := srv.users.Delete(ctx, id.String()); err != nil {
		if errors.Is(err, ErrNotFound) {
			return srv.NotFound(w, r)
		}
		return srv.sendError(w, r, err)
	}
	return protocol.Send(w, http.StatusNoContent, nil)
}

func (srv *Server) NotFound(w http.ResponseWriter, r *http.Request) error {
	return protocol.SendError(w, protocol.ErrNotFound("Endpoint or resource does not exist"))
}

func (srv *Server) validateUser(user *core.User) *protocol.Error {
	if user.UserName == "" {
		return protocol.ErrInvalidValue(`"userName" is required`)
	}
	if !slices.Contains(user.Schemas, core.SchemaUser) {
		return protocol.ErrInvalidValue(`"schemas" must include the User schema URN`)
	}
	return nil
}

func (srv *Server) decodeUser(r *http.Request) (*core.User, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			return nil, protocol.ErrTooLarge("the request body is too large")
		}
		return nil, protocol.ErrInvalidSyntax("could not read the request body")
	}

	user := new(core.User)
	if err := json.Unmarshal(body, user); err != nil {
		return nil, protocol.ErrInvalidSyntax("request body is not a valid User")
	}
	return user, nil
}

func (srv *Server) list[T any](w http.ResponseWriter, r *http.Request, resources []T) error {
	if rejected, err := srv.rejectFilter(w, r, protocol.ErrForbidden("Filtering is not supported on this endpoint")); rejected {
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
	return srv.NotFound(w, r)
}

func (srv *Server) sendError(w http.ResponseWriter, r *http.Request, err error) error {
	if scimErr, ok := errors.AsType[*protocol.Error](err); ok {
		return protocol.SendError(w, scimErr)
	}
	return srv.internalError(w, r, err)
}

func (srv *Server) internalError(w http.ResponseWriter, r *http.Request, err error) error {
	observability.LogEntrySetField(r, "error", err.Error())
	return protocol.SendError(w, protocol.ErrInternal("Internal server error"))
}

func (srv *Server) unauthorized(w http.ResponseWriter) error {
	w.Header().Set("WWW-Authenticate", `Bearer realm="SCIM"`)
	return protocol.SendError(w, protocol.ErrUnauthorized("Bearer token is missing or invalid"))
}

func (srv *Server) rejectFilter(w http.ResponseWriter, r *http.Request, unsupported *protocol.Error) (bool, error) {
	if !r.URL.Query().Has("filter") {
		return false, nil
	}
	return true, protocol.SendError(w, unsupported)
}

func (srv *Server) tenant(w http.ResponseWriter, r *http.Request) (context.Context, bool) {
	ctx := r.Context()

	tenant, err := srv.lookup(ctx, shared.Credential(r))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			_ = srv.unauthorized(w)
		} else {
			_ = srv.internalError(w, r, err)
		}
		return nil, false
	}

	return tenantKey.WithValue(ctx, tenant), true
}

func (srv *Server) lookup(ctx context.Context, bearerToken string) (*Tenant, error) {
	if !strings.HasPrefix(bearerToken, models.SCIMTokenPrefix) {
		return nil, ErrNotFound
	}

	provider, err := models.FindSSOProviderBySCIMToken(srv.db.WithContext(ctx), bearerToken)
	if err != nil {
		if errors.Is(err, models.SSOProviderNotFoundError{}) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scim: looking up token: %w", err)
	}

	return provider, nil
}

func newUserSchema(baseURL string) *core.Schema {
	schema := &core.Schema{
		Schemas: []core.SchemaURI{core.SchemaSchema},
		ID:      core.SchemaUser,
		Name:    "User",
		Meta: core.Meta{
			ResourceType: "Schema",
			Location:     Join(Join(baseURL, "/Schemas"), string(core.SchemaUser)),
		},
	}

	return schema.
		Describe("User Account").
		With(
			core.NewAttribute("userName", core.TypeString, "Unique identifier for the User").
				AsRequired().
				UniqueOn(core.UniquenessServer),

			core.NewAttribute("name", core.TypeComplex, "The components of the user's name.").
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
