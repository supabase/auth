package api

import (
	"net/http"
	"slices"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/observability"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/utilities"
)

// TODO: Admin Audit Logging for Custom OAuth/OIDC Providers
//
// Current state: No audit logging is implemented for provider management operations.
//
// Why: The existing audit logging system (models.NewAuditLogEntry) is designed for
// user-centric actions where there's always a "user actor" performing an action.
// Admin infrastructure operations like provider management are different:
// - They're admin-only configuration changes
// - They don't have a regular "user" as the actor (it's an admin/operator)
// - They need different metadata (who made the change, what was changed, when, from where)
//
// What's needed:
// 1. Design a separate admin audit log system or extend the existing one
// 2. Consider what should be logged:
//    - WHO: Admin identifier (could be service role, API key, or admin user)
//    - WHAT: Operation (create/update/delete provider)
//    - WHEN: Timestamp
//    - WHERE: IP address, request ID
//    - DETAILS: Provider identifier, what changed (for updates)
// 3. Consider compliance requirements (SOC2, GDPR, etc.)
// 4. Decide on storage (same audit_log_entries table or separate table?)
//
// For now, all create/update/delete operations have TODO comments where audit
// logging should be added once the design is finalized.

// AdminCustomOAuthProviderParams defines parameters for creating/updating providers
type AdminCustomOAuthProviderParams struct {
	// Common fields
	ProviderType        string                 `json:"provider_type"` // "oauth2" or "oidc"
	Identifier          string                 `json:"identifier"`
	Name                string                 `json:"name"`
	ClientID            string                 `json:"client_id"`
	ClientSecret        string                 `json:"client_secret"`
	AcceptableClientIDs []string               `json:"acceptable_client_ids,omitempty"`
	Scopes              []string               `json:"scopes"`
	PKCEEnabled         *bool                  `json:"pkce_enabled,omitempty"`
	AttributeMapping    map[string]interface{} `json:"attribute_mapping,omitempty"`
	AuthorizationParams map[string]interface{} `json:"authorization_params,omitempty"`
	Enabled             *bool                  `json:"enabled,omitempty"`
	EmailOptional       *bool                  `json:"email_optional,omitempty"`

	// OIDC-specific fields
	Issuer         string  `json:"issuer,omitempty"`
	DiscoveryURL   *string `json:"discovery_url,omitempty"`
	SkipNonceCheck *bool   `json:"skip_nonce_check,omitempty"`

	// OAuth2-specific fields
	AuthorizationURL string  `json:"authorization_url,omitempty"`
	TokenURL         string  `json:"token_url,omitempty"`
	UserinfoURL      string  `json:"userinfo_url,omitempty"`
	JwksURI          *string `json:"jwks_uri,omitempty"`
}

// ===================================
// Provider Admin Endpoints
// ===================================

// adminCustomOAuthProvidersList returns all custom OAuth/OIDC providers
func (a *API) adminCustomOAuthProvidersList(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)

	// Check for optional type filter
	providerTypeParam := r.URL.Query().Get("type")
	var providers []*models.CustomOAuthProvider
	var err error

	if providerTypeParam != "" {
		// Validate type parameter
		providerType := models.ProviderType(providerTypeParam)
		if providerType != models.ProviderTypeOAuth2 && providerType != models.ProviderTypeOIDC {
			return apierrors.NewBadRequestError(
				apierrors.ErrorCodeValidationFailed,
				"type must be either 'oauth2' or 'oidc'",
			)
		}
		providers, err = models.FindAllCustomOAuthProvidersByType(db, providerType)
	} else {
		providers, err = models.FindAllCustomOAuthProviders(db)
	}

	if err != nil {
		return apierrors.NewInternalServerError("Error retrieving custom OAuth providers").WithInternalError(err)
	}

	return sendJSON(w, http.StatusOK, map[string]interface{}{
		"providers": providers,
	})
}

// adminCustomOAuthProviderGet returns a single custom OAuth/OIDC provider
func (a *API) adminCustomOAuthProviderGet(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)

	identifier := chi.URLParam(r, "identifier")
	if identifier == "" {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "identifier is required")
	}

	// Validate identifier starts with 'custom:' prefix
	if !strings.HasPrefix(identifier, "custom:") {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "identifier must start with 'custom:' prefix")
	}

	observability.LogEntrySetField(r, "identifier", identifier)

	provider, err := models.FindCustomOAuthProviderByIdentifier(db, identifier)
	if err != nil {
		if models.IsNotFoundError(err) {
			return apierrors.NewNotFoundError(apierrors.ErrorCodeProviderNotFound, "Custom OAuth provider not found")
		}
		return apierrors.NewInternalServerError("Error retrieving custom OAuth provider").WithInternalError(err)
	}

	return sendJSON(w, http.StatusOK, provider)
}

// adminCustomOAuthProviderCreate creates a new custom OAuth/OIDC provider
func (a *API) adminCustomOAuthProviderCreate(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	config := a.config

	// Check if custom OAuth is enabled
	if !config.CustomOAuth.Enabled {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeFeatureDisabled, "Custom OAuth/OIDC providers are not enabled")
	}

	// Parse request parameters
	params := &AdminCustomOAuthProviderParams{}
	if err := retrieveRequestParams(r, params); err != nil {
		return err
	}

	// Validate provider type
	if params.ProviderType != string(models.ProviderTypeOAuth2) && params.ProviderType != string(models.ProviderTypeOIDC) {
		return apierrors.NewBadRequestError(
			apierrors.ErrorCodeValidationFailed,
			"provider_type must be either 'oauth2' or 'oidc'",
		)
	}

	providerType := models.ProviderType(params.ProviderType)

	// Validate type-specific required fields
	if err := validateProviderParams(params, providerType); err != nil {
		return err
	}

	// Validate authorization params (no reserved OAuth parameters)
	if err := validateAuthorizationParams(params.AuthorizationParams); err != nil {
		return err
	}

	// Validate attribute mapping (no protected system fields)
	if err := validateAttributeMapping(params.AttributeMapping); err != nil {
		return err
	}

	// Check quota if configured
	if config.CustomOAuth.MaxProviders > 0 {
		totalCount, err := models.CountCustomOAuthProviders(db)
		if err != nil {
			return apierrors.NewInternalServerError("Error checking provider quota").WithInternalError(err)
		}
		if totalCount >= config.CustomOAuth.MaxProviders {
			return apierrors.NewBadRequestError(
				apierrors.ErrorCodeOverQuota,
				"Maximum number of custom OAuth/OIDC providers reached",
			)
		}
	}

	// Validate URLs based on provider type
	if err := validateProviderURLs(params, providerType); err != nil {
		return err
	}

	// Check if provider with this identifier already exists
	existingProvider, err := models.FindCustomOAuthProviderByIdentifier(db, params.Identifier)
	if err != nil && !models.IsNotFoundError(err) {
		return apierrors.NewInternalServerError("Error checking for existing provider").WithInternalError(err)
	}
	if existingProvider != nil {
		return apierrors.NewBadRequestError(
			apierrors.ErrorCodeConflict,
			"A custom OAuth provider with this identifier already exists",
		)
	}

	// Create provider model
	provider := buildProviderFromParams(params, providerType)

	// Encrypt and store client secret
	if err := provider.SetClientSecret(params.ClientSecret, config.Security.DBEncryption); err != nil {
		return apierrors.NewInternalServerError("Error encrypting custom OAuth provider client secret").WithInternalError(err)
	}

	// Create in database
	err = db.Transaction(func(tx *storage.Connection) error {
		if terr := models.CreateCustomOAuthProvider(tx, provider); terr != nil {
			return terr
		}

		// TODO: Implement proper admin audit logging for infrastructure changes
		// The current audit log is user-centric. We need a separate audit mechanism
		// for admin operations like provider management that doesn't require a "user actor"
		// but tracks admin API changes for security and compliance.

		return nil
	})

	if err != nil {
		return apierrors.NewInternalServerError("Error creating custom OAuth provider").WithInternalError(err)
	}

	return sendJSON(w, http.StatusCreated, provider)
}

// adminCustomOAuthProviderUpdate updates an existing custom OAuth/OIDC provider
func (a *API) adminCustomOAuthProviderUpdate(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	config := a.config

	identifier := chi.URLParam(r, "identifier")
	if identifier == "" {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "identifier is required")
	}

	// Validate identifier starts with 'custom:' prefix
	if !strings.HasPrefix(identifier, "custom:") {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "identifier must start with 'custom:' prefix")
	}

	observability.LogEntrySetField(r, "identifier", identifier)

	// Parse request parameters
	params := &AdminCustomOAuthProviderParams{}
	if err := retrieveRequestParams(r, params); err != nil {
		return err
	}

	// Validate authorization params if provided
	if params.AuthorizationParams != nil {
		if err := validateAuthorizationParams(params.AuthorizationParams); err != nil {
			return err
		}
	}

	// Validate attribute mapping if provided
	if params.AttributeMapping != nil {
		if err := validateAttributeMapping(params.AttributeMapping); err != nil {
			return err
		}
	}

	var provider *models.CustomOAuthProvider
	err := db.Transaction(func(tx *storage.Connection) error {
		var terr error
		provider, terr = models.FindCustomOAuthProviderByIdentifier(tx, identifier)
		if terr != nil {
			if models.IsNotFoundError(terr) {
				return apierrors.NewNotFoundError(apierrors.ErrorCodeProviderNotFound, "Custom OAuth provider not found")
			}
			return apierrors.NewInternalServerError("Error retrieving custom OAuth provider").WithInternalError(terr)
		}

		// Update provider with new non-secret values
		if terr := updateProviderFromParams(provider, params); terr != nil {
			return terr
		}

		// If a new client secret is provided, encrypt and store it (likely move to out of the transaction)
		if params.ClientSecret != "" {
			if terr := provider.SetClientSecret(params.ClientSecret, config.Security.DBEncryption); terr != nil {
				return apierrors.NewInternalServerError("Error encrypting custom OAuth provider client secret").WithInternalError(terr)
			}
		}

		if terr := models.UpdateCustomOAuthProvider(tx, provider); terr != nil {
			return apierrors.NewInternalServerError("Error updating custom OAuth provider").WithInternalError(terr)
		}

		// TODO: Add admin audit logging here (see create endpoint for details)

		return nil
	})

	if err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, provider)
}

// adminCustomOAuthProviderDelete deletes a custom OAuth/OIDC provider
func (a *API) adminCustomOAuthProviderDelete(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)

	identifier := chi.URLParam(r, "identifier")
	if identifier == "" {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "identifier is required")
	}

	// Validate identifier starts with 'custom:' prefix
	if !strings.HasPrefix(identifier, "custom:") {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "identifier must start with 'custom:' prefix")
	}

	observability.LogEntrySetField(r, "identifier", identifier)

	err := db.Transaction(func(tx *storage.Connection) error {
		provider, terr := models.FindCustomOAuthProviderByIdentifier(tx, identifier)
		if terr != nil {
			if models.IsNotFoundError(terr) {
				return apierrors.NewNotFoundError(apierrors.ErrorCodeProviderNotFound, "Custom OAuth provider not found")
			}
			return apierrors.NewInternalServerError("Error retrieving custom OAuth provider").WithInternalError(terr)
		}

		// TODO: Add admin audit logging here (see create endpoint for details)

		if terr := models.DeleteCustomOAuthProvider(tx, provider.ID); terr != nil {
			return apierrors.NewInternalServerError("Error deleting custom OAuth provider").WithInternalError(terr)
		}

		return nil
	})

	if err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Custom OAuth provider deleted successfully",
	})
}

// ===================================
// Helper Functions
// ===================================

// validateProviderParams validates type-specific required fields
func validateProviderParams(params *AdminCustomOAuthProviderParams, providerType models.ProviderType) error {
	// Common validations
	if params.Identifier == "" {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "identifier is required")
	}

	// Ensure identifier starts with 'custom:' prefix
	if !strings.HasPrefix(params.Identifier, "custom:") {
		params.Identifier = "custom:" + params.Identifier
	}

	// Check for reserved provider names (built-in OAuth providers)
	// These are already handled by Supabase Auth and shouldn't be overridden with custom providers
	reservedProviderNames := []string{
		"apple", "azure", "bitbucket", "discord", "facebook", "figma", "fly", "github", "gitlab",
		"google", "kakao", "keycloak", "linkedin_oidc", "linkedin", "notion", "slack_oidc",
		"slack", "spotify", "twitch", "twitter", "workos", "x", "zoom",
	}

	// Extract the base identifier without the "custom:" prefix for checking
	baseIdentifier := strings.TrimPrefix(params.Identifier, "custom:")
	if slices.Contains(reservedProviderNames, strings.ToLower(baseIdentifier)) {
		return apierrors.NewBadRequestError(
			apierrors.ErrorCodeValidationFailed,
			"Cannot use reserved provider name: %s. This provider is already built into Supabase Auth.",
			baseIdentifier,
		)
	}

	if params.Name == "" {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "name is required")
	}
	if params.ClientID == "" {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "client_id is required")
	}
	if params.ClientSecret == "" {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "client_secret is required")
	}

	// Type-specific validations
	if providerType == models.ProviderTypeOIDC {
		if params.Issuer == "" {
			return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "issuer is required for OIDC providers")
		}
	} else if providerType == models.ProviderTypeOAuth2 {
		if params.AuthorizationURL == "" {
			return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "authorization_url is required for OAuth2 providers")
		}
		if params.TokenURL == "" {
			return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "token_url is required for OAuth2 providers")
		}
		if params.UserinfoURL == "" {
			return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "userinfo_url is required for OAuth2 providers")
		}
	}

	return nil
}

// validateProviderURLs validates URLs with SSRF protection
func validateProviderURLs(params *AdminCustomOAuthProviderParams, providerType models.ProviderType) error {
	var urls []string

	if providerType == models.ProviderTypeOIDC {
		urls = append(urls, params.Issuer)
		if params.DiscoveryURL != nil && *params.DiscoveryURL != "" {
			urls = append(urls, *params.DiscoveryURL)
		}
	} else if providerType == models.ProviderTypeOAuth2 {
		urls = []string{
			params.AuthorizationURL,
			params.TokenURL,
			params.UserinfoURL,
		}
		if params.JwksURI != nil && *params.JwksURI != "" {
			urls = append(urls, *params.JwksURI)
		}
	}

	for _, urlStr := range urls {
		if urlStr != "" {
			if err := utilities.ValidateOAuthURL(urlStr); err != nil {
				return err
			}
		}
	}

	return nil
}

// buildProviderFromParams creates a provider model from params
func buildProviderFromParams(params *AdminCustomOAuthProviderParams, providerType models.ProviderType) *models.CustomOAuthProvider {
	provider := &models.CustomOAuthProvider{
		ProviderType:        providerType,
		Identifier:          params.Identifier,
		Name:                params.Name,
		ClientID:            params.ClientID,
		AcceptableClientIDs: models.StringSlice(params.AcceptableClientIDs),
		Scopes:              models.StringSlice(params.Scopes),
		PKCEEnabled:         getBoolOrDefault(params.PKCEEnabled, true),
		AttributeMapping:    models.OAuthAttributeMapping(params.AttributeMapping),
		AuthorizationParams: models.OAuthAuthorizationParams(params.AuthorizationParams),
		Enabled:             getBoolOrDefault(params.Enabled, true),
		EmailOptional:       getBoolOrDefault(params.EmailOptional, false),
	}

	// Set type-specific fields
	if providerType == models.ProviderTypeOIDC {
		provider.Issuer = &params.Issuer
		provider.DiscoveryURL = params.DiscoveryURL
		provider.SkipNonceCheck = getBoolOrDefault(params.SkipNonceCheck, false)

		// Ensure openid scope is present for OIDC
		hasOpenID := false
		for _, scope := range provider.Scopes {
			if scope == "openid" {
				hasOpenID = true
				break
			}
		}
		if !hasOpenID {
			provider.Scopes = append(models.StringSlice{"openid"}, provider.Scopes...)
		}
	} else if providerType == models.ProviderTypeOAuth2 {
		provider.AuthorizationURL = &params.AuthorizationURL
		provider.TokenURL = &params.TokenURL
		provider.UserinfoURL = &params.UserinfoURL
		provider.JwksURI = params.JwksURI
	}

	// Initialize empty maps if nil
	if provider.AttributeMapping == nil {
		provider.AttributeMapping = make(models.OAuthAttributeMapping)
	}
	if provider.AuthorizationParams == nil {
		provider.AuthorizationParams = make(models.OAuthAuthorizationParams)
	}

	return provider
}

// updateProviderFromParams updates a provider model from params
func updateProviderFromParams(provider *models.CustomOAuthProvider, params *AdminCustomOAuthProviderParams) error {
	// Update common fields
	if params.Name != "" {
		provider.Name = params.Name
	}
	if params.ClientID != "" {
		provider.ClientID = params.ClientID
	}
	if params.AcceptableClientIDs != nil {
		provider.AcceptableClientIDs = models.StringSlice(params.AcceptableClientIDs)
	}
	if params.Scopes != nil {
		provider.Scopes = models.StringSlice(params.Scopes)
		// Ensure openid scope for OIDC
		if provider.IsOIDC() {
			hasOpenID := false
			for _, scope := range provider.Scopes {
				if scope == "openid" {
					hasOpenID = true
					break
				}
			}
			if !hasOpenID {
				provider.Scopes = append(models.StringSlice{"openid"}, provider.Scopes...)
			}
		}
	}
	if params.PKCEEnabled != nil {
		provider.PKCEEnabled = *params.PKCEEnabled
	}
	if params.AttributeMapping != nil {
		provider.AttributeMapping = models.OAuthAttributeMapping(params.AttributeMapping)
	}
	if params.AuthorizationParams != nil {
		provider.AuthorizationParams = models.OAuthAuthorizationParams(params.AuthorizationParams)
	}
	if params.Enabled != nil {
		provider.Enabled = *params.Enabled
	}
	if params.EmailOptional != nil {
		provider.EmailOptional = *params.EmailOptional
	}

	// Update type-specific fields
	if provider.IsOIDC() {
		if params.Issuer != "" {
			if err := utilities.ValidateOAuthURL(params.Issuer); err != nil {
				return err
			}
			provider.Issuer = &params.Issuer
		}
		if params.DiscoveryURL != nil {
			provider.DiscoveryURL = params.DiscoveryURL
		}
		if params.SkipNonceCheck != nil {
			provider.SkipNonceCheck = *params.SkipNonceCheck
		}
	} else if provider.IsOAuth2() {
		if params.AuthorizationURL != "" {
			provider.AuthorizationURL = &params.AuthorizationURL
		}
		if params.TokenURL != "" {
			provider.TokenURL = &params.TokenURL
		}
		if params.UserinfoURL != "" {
			provider.UserinfoURL = &params.UserinfoURL
		}
		if params.JwksURI != nil {
			provider.JwksURI = params.JwksURI
		}
	}

	return nil
}

// getBoolOrDefault returns the value or default if nil
func getBoolOrDefault(value *bool, defaultValue bool) bool {
	if value == nil {
		return defaultValue
	}
	return *value
}

// validateAuthorizationParams ensures no reserved OAuth parameters are overridden
func validateAuthorizationParams(params map[string]interface{}) error {
	if params == nil {
		return nil
	}

	// Reserved OAuth2/OIDC parameters that should never be overridden
	// These are set by the auth server and allowing override would be a security issue
	reservedParams := []string{
		"client_id",
		"client_secret",
		"redirect_uri",
		"response_type",
		"state",
		"code_challenge",
		"code_challenge_method",
		"code_verifier",
		"nonce", // We control nonce generation for security
	}

	for key := range params {
		if slices.Contains(reservedParams, key) {
			return apierrors.NewBadRequestError(
				apierrors.ErrorCodeValidationFailed,
				"Cannot override reserved OAuth parameter: %s", key,
			)
		}
	}

	return nil
}

// validateAttributeMapping ensures no sensitive system fields are targeted
func validateAttributeMapping(mapping map[string]interface{}) error {
	if mapping == nil {
		return nil
	}

	// System fields that should never be populated from external providers
	// Allowing these could lead to privilege escalation or security bypass
	blockedTargets := []string{
		"id",           // User UUID - system generated
		"aud",          // JWT audience - system controlled
		"role",         // User role - should be managed via database, not external provider
		"app_metadata", // Admin-only metadata - not for external providers
		"created_at",   // System timestamp
		"updated_at",   // System timestamp
		"confirmed_at", // Email confirmation - system controlled
		"email_confirmed_at",
		"phone_confirmed_at",
		"banned_until",   // Security field - system controlled
		"is_super_admin", // Admin flag - system controlled
	}

	for targetField := range mapping {
		if slices.Contains(blockedTargets, targetField) {
			return apierrors.NewBadRequestError(
				apierrors.ErrorCodeValidationFailed,
				"Cannot map to protected system field: %s", targetField,
			)
		}
	}

	return nil
}
