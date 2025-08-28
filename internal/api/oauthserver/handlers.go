package oauthserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/api/shared"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/observability"
	"github.com/supabase/auth/internal/utilities"
)

// OAuthServerClientResponse represents the response format for OAuth client operations
type OAuthServerClientResponse struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"` // only returned on registration

	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	TokenEndpointAuthMethod []string `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	ClientName              string   `json:"client_name,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`

	// Metadata fields
	RegistrationType string    `json:"registration_type,omitempty"`
	CreatedAt        time.Time `json:"created_at,omitempty"`
	UpdatedAt        time.Time `json:"updated_at,omitempty"`
}

// OAuthServerClientListResponse represents the response for listing OAuth clients
type OAuthServerClientListResponse struct {
	Clients []OAuthServerClientResponse `json:"clients,omitempty"`
}

// oauthServerClientToResponse converts a model to response format
func oauthServerClientToResponse(client *models.OAuthServerClient, includeSecret bool) *OAuthServerClientResponse {
	response := &OAuthServerClientResponse{
		ClientID: client.ClientID,

		// OAuth 2.1 DCR fields
		RedirectURIs:            client.GetRedirectURIs(),
		TokenEndpointAuthMethod: []string{"client_secret_basic", "client_secret_post"}, // Both methods are supported
		GrantTypes:              client.GetGrantTypes(),
		ResponseTypes:           []string{"code"}, // Always "code" in OAuth 2.1
		ClientName:              utilities.StringValue(client.ClientName),
		ClientURI:               utilities.StringValue(client.ClientURI),
		LogoURI:                 utilities.StringValue(client.LogoURI),

		// Metadata fields
		RegistrationType: client.RegistrationType,
		CreatedAt:        client.CreatedAt,
		UpdatedAt:        client.UpdatedAt,
	}

	// Only include client_secret during registration
	if includeSecret {
		// Note: This will be filled in by the handler with the plaintext secret
		response.ClientSecret = ""
	}

	return response
}

// LoadOAuthServerClient is middleware that loads an OAuth server client from the URL parameter
func (s *Server) LoadOAuthServerClient(w http.ResponseWriter, r *http.Request) (context.Context, error) {
	ctx := r.Context()
	clientID := chi.URLParam(r, "client_id")

	if clientID == "" {
		return nil, apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "client_id is required")
	}

	observability.LogEntrySetField(r, "oauth_client_id", clientID)

	client, err := s.getOAuthServerClient(ctx, clientID)
	if err != nil {
		if models.IsNotFoundError(err) {
			return nil, apierrors.NewNotFoundError(apierrors.ErrorCodeOAuthClientNotFound, "OAuth client not found")
		}
		return nil, apierrors.NewInternalServerError("Error loading OAuth client").WithInternalError(err)
	}

	ctx = WithOAuthServerClient(ctx, client)
	return ctx, nil
}

// AdminOAuthServerClientRegister handles POST /admin/oauth/clients (manual registration by admins)
func (s *Server) AdminOAuthServerClientRegister(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	var params OAuthServerClientRegisterParams
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeBadJSON, "Invalid JSON body")
	}

	// Force registration type to manual for admin endpoint
	params.RegistrationType = "manual"

	client, plaintextSecret, err := s.registerOAuthServerClient(ctx, &params)
	if err != nil {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, err.Error())
	}

	response := oauthServerClientToResponse(client, true)
	response.ClientSecret = plaintextSecret

	return shared.SendJSON(w, http.StatusCreated, response)
}

// OAuthServerClientDynamicRegister handles POST /oauth/register (OAuth 2.1 Dynamic Client Registration)
func (s *Server) OAuthServerClientDynamicRegister(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	// Check if dynamic registration is enabled
	if !s.config.OAuthServer.AllowDynamicRegistration {
		return apierrors.NewForbiddenError(apierrors.ErrorCodeOAuthDynamicClientRegistrationDisabled, "Dynamic client registration is not enabled")
	}

	var params OAuthServerClientRegisterParams
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeBadJSON, "Invalid JSON body")
	}

	params.RegistrationType = "dynamic"

	client, plaintextSecret, err := s.registerOAuthServerClient(ctx, &params)
	if err != nil {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, err.Error())
	}

	response := oauthServerClientToResponse(client, true)
	response.ClientSecret = plaintextSecret

	return shared.SendJSON(w, http.StatusCreated, response)
}

// OAuthServerClientGet handles GET /admin/oauth/clients/{client_id}
func (s *Server) OAuthServerClientGet(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	client := GetOAuthServerClient(ctx)

	response := oauthServerClientToResponse(client, false)
	return shared.SendJSON(w, http.StatusOK, response)
}

// OAuthServerClientDelete handles DELETE /admin/oauth/clients/{client_id}
func (s *Server) OAuthServerClientDelete(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	client := GetOAuthServerClient(ctx)

	if err := s.deleteOAuthServerClient(ctx, client.ClientID); err != nil {
		return apierrors.NewInternalServerError("Error deleting OAuth client").WithInternalError(err)
	}

	w.WriteHeader(http.StatusNoContent)
	return nil
}

// OAuthServerClientList handles GET /admin/oauth/clients
func (s *Server) OAuthServerClientList(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := s.db.WithContext(ctx)

	var clients []models.OAuthServerClient
	if err := db.Q().Where("deleted_at is null").Order("created_at desc").All(&clients); err != nil {
		return apierrors.NewInternalServerError("Error listing OAuth clients").WithInternalError(err)
	}

	responses := make([]OAuthServerClientResponse, len(clients))
	for i, client := range clients {
		responses[i] = *oauthServerClientToResponse(&client, false)
	}

	response := OAuthServerClientListResponse{
		Clients: responses,
	}

	return shared.SendJSON(w, http.StatusOK, response)
}

// OAuthServerMetadataResponse represents the OAuth 2.1 Authorization Server Metadata per RFC 8414
type OAuthServerMetadataResponse struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	JWKSetURI                         string   `json:"jwks_uri"`
	RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`

	// TODO(cemal) :: Append the scopes supported when scope management is clarified!
	// ScopesSupported                   []string `json:"scopes_supported"`
}

// OAuthServerMetadata handles GET /.well-known/oauth-authorization-server
func (s *Server) OAuthServerMetadata(w http.ResponseWriter, r *http.Request) error {
	issuer := s.config.JWT.Issuer

	// TODO(cemal) :: Remove this check when we have the config validation in place
	if issuer == "" {
		return apierrors.NewInternalServerError("Issuer is not set")
	}

	response := OAuthServerMetadataResponse{
		Issuer:                            issuer,
		AuthorizationEndpoint:             fmt.Sprintf("%s/oauth/authorize", issuer),
		TokenEndpoint:                     fmt.Sprintf("%s/oauth/token", issuer),
		JWKSetURI:                         fmt.Sprintf("%s/.well-known/jwks.json", issuer),
		ResponseTypesSupported:            []string{"code"},
		ResponseModesSupported:            []string{"query"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post"},
		CodeChallengeMethodsSupported:     []string{"S256", "plain"},
	}

	// Include registration endpoint if dynamic registration is enabled
	if s.config.OAuthServer.AllowDynamicRegistration {
		response.RegistrationEndpoint = fmt.Sprintf("%s/oauth/clients/register", issuer)
	}

	// TODO: Cache response for 10 minutes, but consider dynamic registration toggle changes
	return shared.SendJSON(w, http.StatusOK, response)
}
