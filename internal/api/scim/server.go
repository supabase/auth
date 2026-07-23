package scim

import (
	"net/http"

	"github.com/supabase/auth/internal/api/shared"
)

const mediaType = "application/scim+json"

const schemaServiceProviderConfig = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"

type Server struct {
}

func NewServer() *Server {
	return &Server{}
}

func (srv *Server) ServiceProviderConfig(w http.ResponseWriter, r *http.Request) error {
	return shared.SendJSONAs(w, http.StatusOK, mediaType, &ServiceProviderConfig{
		Schemas:        []string{schemaServiceProviderConfig},
		Patch:          SupportedFeature{Supported: false},
		Bulk:           BulkFeature{Supported: false, MaxOperations: 0, MaxPayloadSize: 0},
		Filter:         FilterFeature{Supported: false, MaxResults: 0},
		ChangePassword: SupportedFeature{Supported: false},
		Sort:           SupportedFeature{Supported: false},
		ETag:           SupportedFeature{Supported: false},
		AuthenticationSchemes: []AuthenticationScheme{
			{
				Type:        "httpbearertoken",
				Name:        "Bearer Token",
				Description: "Authentication using a per-provider bearer token",
				SpecURI:     "http://www.rfc-editor.org/info/rfc6750",
				Primary:     true,
			},
		},
	})
}

func (srv *Server) ResourceTypes(w http.ResponseWriter, r *http.Request) error {
	return shared.SendJSONAs(w, http.StatusOK, mediaType, NewListResponse([]any{}))
}

func (srv *Server) Schemas(w http.ResponseWriter, r *http.Request) error {
	return shared.SendJSONAs(w, http.StatusOK, mediaType, NewListResponse([]any{}))
}
