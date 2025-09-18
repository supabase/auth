package oauthserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/api/shared"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/observability"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/tokens"
	"github.com/supabase/auth/internal/utilities"
)

// OAuth 2.1 Grant Types
const (
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeRefreshToken      = "refresh_token"
)

// OAuthServerClientResponse represents the response format for OAuth client operations
type OAuthServerClientResponse struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"` // only returned on registration
	ClientType   string `json:"client_type"`

	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
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
func oauthServerClientToResponse(client *models.OAuthServerClient) *OAuthServerClientResponse {
	// Set token endpoint auth methods based on client type
	var tokenEndpointAuthMethods string
	// TODO(cemal) :: Remove this once we have the token endpoint auth method stored in the database
	if client.IsPublic() {
		// Public clients don't use client authentication
		tokenEndpointAuthMethods = models.TokenEndpointAuthMethodNone
	} else {
		// Confidential clients use client secret authentication
		tokenEndpointAuthMethods = models.TokenEndpointAuthMethodClientSecretBasic
	}

	response := &OAuthServerClientResponse{
		ClientID:   client.ID.String(),
		ClientType: client.ClientType,

		// OAuth 2.1 DCR fields
		RedirectURIs:            client.GetRedirectURIs(),
		TokenEndpointAuthMethod: tokenEndpointAuthMethods,
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

	return response
}

// LoadOAuthServerClient is middleware that loads an OAuth server client from the URL parameter
func (s *Server) LoadOAuthServerClient(w http.ResponseWriter, r *http.Request) (context.Context, error) {
	ctx := r.Context()
	clientIDStr := chi.URLParam(r, "client_id")

	if clientIDStr == "" {
		return nil, apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "client_id is required")
	}

	// Parse client_id as UUID
	clientID, err := uuid.FromString(clientIDStr)
	if err != nil {
		return nil, apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "invalid client_id format")
	}

	observability.LogEntrySetField(r, "oauth_client_id", clientIDStr)

	client, err := s.getOAuthServerClient(ctx, clientID)
	if err != nil {
		if models.IsNotFoundError(err) {
			return nil, apierrors.NewNotFoundError(apierrors.ErrorCodeOAuthClientNotFound, "OAuth client not found")
		}
		return nil, apierrors.NewInternalServerError("Error loading OAuth client").WithInternalError(err)
	}

	ctx = shared.WithOAuthServerClient(ctx, client)
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

	response := oauthServerClientToResponse(client)
	if client.IsConfidential() {
		response.ClientSecret = plaintextSecret
	}

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

	response := oauthServerClientToResponse(client)
	if client.IsConfidential() {
		response.ClientSecret = plaintextSecret
	}

	return shared.SendJSON(w, http.StatusCreated, response)
}

// OAuthServerClientGet handles GET /admin/oauth/clients/{client_id}
func (s *Server) OAuthServerClientGet(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	client := shared.GetOAuthServerClient(ctx)

	response := oauthServerClientToResponse(client)
	return shared.SendJSON(w, http.StatusOK, response)
}

// OAuthServerClientDelete handles DELETE /admin/oauth/clients/{client_id}
func (s *Server) OAuthServerClientDelete(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	client := shared.GetOAuthServerClient(ctx)

	if err := s.deleteOAuthServerClient(ctx, client.ID); err != nil {
		return apierrors.NewInternalServerError("Error deleting OAuth client").WithInternalError(err)
	}

	w.WriteHeader(http.StatusNoContent)
	return nil
}

// OAuthServerClientRegenerateSecret handles POST /admin/oauth/clients/{client_id}/regenerate_secret
func (s *Server) OAuthServerClientRegenerateSecret(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	client := shared.GetOAuthServerClient(ctx)

	// Only confidential clients can have their secrets regenerated
	if !client.IsConfidential() {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Cannot regenerate secret for public client")
	}

	updatedClient, plaintextSecret, err := s.regenerateOAuthServerClientSecret(ctx, client.ID)
	if err != nil {
		return apierrors.NewInternalServerError("Error regenerating OAuth client secret").WithInternalError(err)
	}

	response := oauthServerClientToResponse(updatedClient)
	response.ClientSecret = plaintextSecret

	return shared.SendJSON(w, http.StatusOK, response)
}

// OAuthServerClientList handles GET /admin/oauth/clients
func (s *Server) OAuthServerClientList(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := s.db.WithContext(ctx)

	// TODO(cemal) :: Add pagination, check the `/admin/users` endpoint for reference
	var clients []models.OAuthServerClient
	if err := db.Q().Where("deleted_at is null").Order("created_at desc").All(&clients); err != nil {
		return apierrors.NewInternalServerError("Error listing OAuth clients").WithInternalError(err)
	}

	responses := make([]OAuthServerClientResponse, len(clients))
	for i, client := range clients {
		responses[i] = *oauthServerClientToResponse(&client)
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

	// Basic issuer validation - empty issuer would create broken URLs
	if issuer == "" {
		return apierrors.NewInternalServerError("Issuer is not set")
	}

	// Ensure issuer doesn't end with a slash to avoid double slashes in URLs
	issuer = strings.TrimSuffix(issuer, "/")

	response := OAuthServerMetadataResponse{
		Issuer:                            issuer,
		AuthorizationEndpoint:             fmt.Sprintf("%s/oauth/authorize", issuer),
		TokenEndpoint:                     fmt.Sprintf("%s/oauth/token", issuer),
		JWKSetURI:                         fmt.Sprintf("%s/.well-known/jwks.json", issuer),
		ResponseTypesSupported:            []string{"code"},
		ResponseModesSupported:            []string{"query"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
		TokenEndpointAuthMethodsSupported: []string{models.TokenEndpointAuthMethodClientSecretBasic, models.TokenEndpointAuthMethodClientSecretPost, models.TokenEndpointAuthMethodNone},
		CodeChallengeMethodsSupported:     []string{"S256", "plain"},
	}

	// Include registration endpoint if dynamic registration is enabled
	if s.config.OAuthServer.AllowDynamicRegistration {
		response.RegistrationEndpoint = fmt.Sprintf("%s/oauth/clients/register", issuer)
	}

	// TODO: Cache response for 10 minutes, but consider dynamic registration toggle changes
	return shared.SendJSON(w, http.StatusOK, response)
}

// OAuthTokenParams represents the parameters for the OAuth token endpoint
type OAuthTokenParams struct {
	GrantType    string `json:"grant_type" form:"grant_type"`
	Code         string `json:"code" form:"code"`
	RefreshToken string `json:"refresh_token" form:"refresh_token"`
	RedirectURI  string `json:"redirect_uri" form:"redirect_uri"`
	ClientID     string `json:"client_id" form:"client_id"`
	ClientSecret string `json:"client_secret" form:"client_secret"`
	CodeVerifier string `json:"code_verifier" form:"code_verifier"`
	Resource     string `json:"resource" form:"resource"`
}

// OAuthToken handles POST /oauth/token
func (s *Server) OAuthToken(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	var params OAuthTokenParams

	// Handle both JSON and form-encoded requests
	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") {
		if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
			return apierrors.NewOAuthError("invalid_request", "Invalid JSON body")
		}
	} else {
		// Parse form data
		if err := r.ParseForm(); err != nil {
			return apierrors.NewOAuthError("invalid_request", "Failed to parse form data")
		}

		params.GrantType = r.FormValue("grant_type")
		params.Code = r.FormValue("code")
		params.RefreshToken = r.FormValue("refresh_token")
		params.RedirectURI = r.FormValue("redirect_uri")
		params.ClientID = r.FormValue("client_id")
		params.ClientSecret = r.FormValue("client_secret")
		params.CodeVerifier = r.FormValue("code_verifier")
	}

	// Validate grant_type
	if params.GrantType == "" {
		return apierrors.NewOAuthError("invalid_request", "grant_type is required")
	}

	client := shared.GetOAuthServerClient(ctx)
	if client == nil {
		return apierrors.NewOAuthError("invalid_client", "Client authentication required")
	}

	// Validate that the authenticated client is allowed to use the requested grant type
	if !client.IsGrantTypeAllowed(params.GrantType) {
		return apierrors.NewOAuthError("unsupported_grant_type", "Client is not allowed to use grant type: "+params.GrantType)
	}

	switch params.GrantType {
	case GrantTypeAuthorizationCode:
		return s.handleAuthorizationCodeGrant(ctx, w, r, &params)
	case GrantTypeRefreshToken:
		return s.handleRefreshTokenGrant(ctx, w, r, &params)
	default:
		return apierrors.NewOAuthError("unsupported_grant_type", "Unsupported grant type: "+params.GrantType)
	}
}

// handleAuthorizationCodeGrant handles the authorization_code grant type
func (s *Server) handleAuthorizationCodeGrant(ctx context.Context, w http.ResponseWriter, r *http.Request, params *OAuthTokenParams) error {
	if params.Code == "" {
		return apierrors.NewOAuthError("invalid_request", "code is required for authorization_code grant")
	}

	// Get authenticated client from middleware
	client := shared.GetOAuthServerClient(ctx)
	if client == nil {
		return apierrors.NewOAuthError("invalid_client", "Client authentication required")
	}

	// Exchange authorization code for tokens
	db := s.db.WithContext(ctx)
	tokenService := s.getTokenService()
	if tokenService == nil {
		return apierrors.NewInternalServerError("Token service not available")
	}

	// Find the OAuth authorization for this authorization code
	authorization, err := models.FindOAuthServerAuthorizationByCode(db, params.Code)
	if err != nil {
		if models.IsNotFoundError(err) {
			return apierrors.NewOAuthError("invalid_grant", "Invalid authorization code")
		}
		return apierrors.NewInternalServerError("Error finding authorization code").WithInternalError(err)
	}

	// Check if the authorization has expired
	if authorization.IsExpired() {
		return apierrors.NewOAuthError("invalid_grant", "Authorization code has expired")
	}

	// Validate that the authorization code was issued for this client
	if authorization.ClientID != client.ID {
		return apierrors.NewOAuthError("invalid_grant", "Authorization code was not issued for this client")
	}

	// Validate that (if exists) the resource parameter matches the authorization code resource
	if params.Resource != "" && params.Resource != utilities.StringValue(authorization.Resource) {
		return apierrors.NewOAuthError("invalid_grant", "Authorization code resource does not match the resource parameter")
	}

	// Validate redirect_uri if provided - must match the one used in authorization
	if params.RedirectURI != "" && params.RedirectURI != authorization.RedirectURI {
		return apierrors.NewOAuthError("invalid_grant", "Invalid redirect_uri")
	}

	// Validate PKCE if used in the authorization
	if err := authorization.VerifyPKCE(params.CodeVerifier); err != nil {
		return apierrors.NewOAuthError("invalid_grant", "PKCE verification failed: "+err.Error())
	}

	// Get the user for the authorization code
	if authorization.UserID == nil {
		return apierrors.NewOAuthError("invalid_grant", "Authorization code has no associated user")
	}

	user, err := models.FindUserByID(db, *authorization.UserID)
	if err != nil {
		if models.IsNotFoundError(err) {
			return apierrors.NewOAuthError("invalid_grant", "User not found for authorization code")
		}
		return apierrors.NewInternalServerError("Error finding user").WithInternalError(err)
	}

	if user.IsBanned() {
		return apierrors.NewOAuthError("access_denied", "User is banned")
	}

	// Exchange the authorization code for tokens
	var tokenResponse *tokens.AccessTokenResponse
	var grantParams models.GrantParams
	grantParams.FillGrantParams(r)
	grantParams.OAuthClientID = &client.ID

	err = db.Transaction(func(tx *storage.Connection) error {
		authMethod := models.OAuthProviderAuthorizationCode

		// Create audit log entry for OAuth token exchange
		if terr := models.NewAuditLogEntry(s.config.AuditLog, r, tx, user, models.LoginAction, "", map[string]interface{}{
			"provider_type": "oauth_provider_authorization_code",
			"client_id":     client.ID.String(),
		}); terr != nil {
			return terr
		}

		// Issue the refresh token and access token
		var terr error
		tokenResponse, terr = tokenService.IssueRefreshToken(r, tx, user, authMethod, grantParams)
		if terr != nil {
			return terr
		}

		// Mark authorization as used - authorization codes are single use
		// We could either delete it or mark it as consumed
		if terr = tx.Destroy(authorization); terr != nil {
			return terr
		}

		return nil
	})

	if err != nil {
		if httpErr, ok := err.(*apierrors.HTTPError); ok {
			return httpErr
		}
		return apierrors.NewInternalServerError("Error exchanging authorization code").WithInternalError(err)
	}

	// Convert to OAuth-compliant response format (exclude user info for OAuth clients)
	oauthResponse := map[string]interface{}{
		"access_token":  tokenResponse.Token,
		"token_type":    tokenResponse.TokenType,
		"expires_in":    tokenResponse.ExpiresIn,
		"refresh_token": tokenResponse.RefreshToken,
	}

	return shared.SendJSON(w, http.StatusOK, oauthResponse)
}

// handleRefreshTokenGrant handles the refresh_token grant type
func (s *Server) handleRefreshTokenGrant(ctx context.Context, w http.ResponseWriter, r *http.Request, params *OAuthTokenParams) error {
	if params.RefreshToken == "" {
		return apierrors.NewOAuthError("invalid_request", "refresh_token is required for refresh_token grant")
	}

	// Use the token service to handle refresh token grant
	tokenService := s.getTokenService()
	if tokenService == nil {
		return apierrors.NewInternalServerError("Token service not available")
	}

	// Get OAuth client from context if present
	var clientID *uuid.UUID
	if oauthClient := shared.GetOAuthServerClient(ctx); oauthClient != nil {
		clientID = &oauthClient.ID
	}

	db := s.db.WithContext(ctx)
	tokenResponse, err := tokenService.RefreshTokenGrant(ctx, db, r, tokens.RefreshTokenGrantParams{
		RefreshToken: params.RefreshToken,
		ClientID:     clientID,
	})
	if err != nil {
		return err
	}

	// Convert to OAuth-compliant response format (exclude user info for OAuth clients)
	oauthResponse := map[string]interface{}{
		"access_token":  tokenResponse.Token,
		"token_type":    tokenResponse.TokenType,
		"expires_in":    tokenResponse.ExpiresIn,
		"refresh_token": tokenResponse.RefreshToken,
	}

	return shared.SendJSON(w, http.StatusOK, oauthResponse)
}

// getTokenService retrieves the token service from the server
func (s *Server) getTokenService() *tokens.Service {
	return s.tokenService
}
