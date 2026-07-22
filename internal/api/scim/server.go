package scim

import (
	"context"
	"net/http"

	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/api/scim/core"
	"github.com/supabase/auth/internal/api/scim/protocol"
	"github.com/supabase/auth/internal/api/shared"
	"github.com/supabase/auth/internal/conf"
)

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
	return shared.SendJSONAs(w, http.StatusOK, protocol.MediaType, &core.ServiceProviderConfig{
		Schemas:        []string{core.SchemaServiceProviderConfig},
		Patch:          core.SupportedFeature{Supported: false},
		Bulk:           core.BulkFeature{Supported: false, MaxOperations: 0, MaxPayloadSize: 0},
		Filter:         core.FilterFeature{Supported: false, MaxResults: 0},
		ChangePassword: core.SupportedFeature{Supported: false},
		Sort:           core.SupportedFeature{Supported: false},
		ETag:           core.SupportedFeature{Supported: false},
		AuthenticationSchemes: []core.AuthenticationScheme{
			{
				Type:        "oauthbearertoken",
				Name:        "OAuth Bearer Token",
				Description: "Authentication using a per-provider bearer token",
				SpecURI:     "http://www.rfc-editor.org/info/rfc6750",
				Primary:     true,
			},
		},
	})
}

func (srv *Server) ResourceTypes(w http.ResponseWriter, r *http.Request) error {
	return shared.SendJSONAs(w, http.StatusOK, protocol.MediaType, protocol.NewListResponse([]any{}))
}

func (srv *Server) Schemas(w http.ResponseWriter, r *http.Request) error {
	return shared.SendJSONAs(w, http.StatusOK, protocol.MediaType, protocol.NewListResponse([]any{}))
}
