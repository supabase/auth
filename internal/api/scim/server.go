package scim

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/go-chi/chi/v5"
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
	Users                 *ResourceServer[*core.User]
	serviceProviderConfig *core.ServiceProviderConfig
	resourceTypes         []*core.ResourceType
	schemas               []*core.Schema
}

func NewServer(db *storage.Connection, externalURL string) *Server {
	baseURL := Join(externalURL, BasePath)
	userSchema := newUserSchema(baseURL)

	users := NewResourceServer(
		protocol.DefaultLimits,
		NewUserService(&userRepository{db: db, baseURL: baseURL, schema: userSchema}),
		ResourceSpec[*core.User]{
			Path:     "/Users",
			Schema:   userSchema,
			New:      func() *core.User { return new(core.User) },
			Validate: validateUser,
			Location: func(u *core.User) string { return u.Meta.Location },
		},
	)

	return &Server{
		db:    db,
		Users: users,
		serviceProviderConfig: newServiceProviderConfig(
			baseURL,
			core.NewOAuthBearerToken().AsPrimary(),
		).Sorting().Filtering(protocol.DefaultLimits.MaxCount),
		resourceTypes: []*core.ResourceType{newUserResourceType(baseURL, userSchema)},
		schemas:       []*core.Schema{userSchema},
	}
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

func NotFound(w http.ResponseWriter, r *http.Request) error {
	return protocol.SendError(w, protocol.ErrNotFound("Endpoint or resource does not exist"))
}

func sendError(w http.ResponseWriter, r *http.Request, err error) error {
	if scimErr, ok := errors.AsType[*protocol.Error](err); ok {
		return protocol.SendError(w, scimErr)
	}
	return internalError(w, r, err)
}

func internalError(w http.ResponseWriter, r *http.Request, err error) error {
	observability.LogEntrySetField(r, "error", err.Error())
	return protocol.SendError(w, protocol.ErrInternal("Internal server error"))
}

func unauthorized(w http.ResponseWriter) error {
	w.Header().Set("WWW-Authenticate", `Bearer realm="SCIM"`)
	return protocol.SendError(w, protocol.ErrUnauthorized("Bearer token is missing or invalid"))
}

func rejectFilter(w http.ResponseWriter, r *http.Request, unsupported *protocol.Error) (bool, error) {
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
			_ = unauthorized(w)
		} else {
			_ = internalError(w, r, err)
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

func urlParam(r *http.Request, key string) string {
	value := chi.URLParam(r, key)

	if decoded, err := url.PathUnescape(value); err == nil {
		return decoded
	}
	return value
}
