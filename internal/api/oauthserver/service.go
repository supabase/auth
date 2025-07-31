package oauthserver

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/pkg/errors"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/crypto"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
	"golang.org/x/crypto/bcrypt"
)

// OAuthServerClientRegisterParams contains parameters for registering a new OAuth client
type OAuthServerClientRegisterParams struct {
	// Required fields
	RedirectURIs []string `json:"redirect_uris"`

	GrantTypes []string `json:"grant_types,omitempty"`
	ClientName string   `json:"client_name,omitempty"`
	ClientURI  string   `json:"client_uri,omitempty"`
	LogoURI    string   `json:"logo_uri,omitempty"`

	// Internal field
	RegistrationType string `json:"-"`
}

// validate validates the OAuth client registration parameters
func (p *OAuthServerClientRegisterParams) validate() error {
	// Validate redirect URIs (required)
	if len(p.RedirectURIs) == 0 {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "redirect_uris is required")
	}

	if len(p.RedirectURIs) > 10 {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "redirect_uris cannot exceed 10 items")
	}

	for _, uri := range p.RedirectURIs {
		if err := validateRedirectURI(uri); err != nil {
			return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "invalid redirect_uri '%s': %v", uri, err)
		}
	}

	for _, grantType := range p.GrantTypes {
		if grantType != "authorization_code" && grantType != "refresh_token" {
			return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "grant_types must only contain 'authorization_code' and/or 'refresh_token'")
		}
	}

	if len(p.ClientName) > 255 {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "client_name cannot exceed 255 characters")
	}

	if p.ClientURI != "" {
		if len(p.ClientURI) > 2048 {
			return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "client_uri cannot exceed 2048 characters")
		}
		if _, err := url.ParseRequestURI(p.ClientURI); err != nil {
			return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "client_uri must be a valid URL")
		}
	}

	if p.LogoURI != "" {
		if len(p.LogoURI) > 2048 {
			return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "logo_uri cannot exceed 2048 characters")
		}
		if _, err := url.ParseRequestURI(p.LogoURI); err != nil {
			return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "logo_uri must be a valid URL")
		}
	}

	if p.RegistrationType != "dynamic" && p.RegistrationType != "manual" {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "registration_type must be 'dynamic' or 'manual'")
	}

	return nil
}

// validateRedirectURI validates OAuth 2.1 redirect URIs
func validateRedirectURI(uri string) error {
	if uri == "" {
		return fmt.Errorf("redirect URI cannot be empty")
	}

	parsedURL, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("invalid URL format")
	}

	// Must have scheme and host
	if parsedURL.Scheme == "" || parsedURL.Host == "" {
		return fmt.Errorf("must have scheme and host")
	}

	// Check scheme requirements
	if parsedURL.Scheme == "http" {
		// HTTP only allowed for localhost
		host := parsedURL.Hostname()
		if host != "localhost" && host != "127.0.0.1" {
			return fmt.Errorf("HTTP scheme only allowed for localhost")
		}
	} else if parsedURL.Scheme != "https" {
		return fmt.Errorf("scheme must be HTTPS or HTTP (localhost only)")
	}

	// Must not have fragment
	if parsedURL.Fragment != "" {
		return fmt.Errorf("fragment not allowed in redirect URI")
	}

	return nil
}

// generateClientID generates a URL-safe random client ID
func generateClientID() string {
	// Generate a 32-character alphanumeric client ID
	return crypto.SecureAlphanumeric(32)
}

// generateClientSecret generates a secure random client secret
func generateClientSecret() string {
	// Generate a 64-character secure random secret
	return crypto.SecureAlphanumeric(64)
}

// hashClientSecret hashes a client secret using bcrypt
func hashClientSecret(secret string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return "", errors.Wrap(err, "failed to hash client secret")
	}
	return string(hash), nil
}

// ValidateClientSecret validates a client secret against its hash
func ValidateClientSecret(secret, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(secret))
	return err == nil
}

// registerOAuthServerClient creates a new OAuth server client with generated credentials
func (s *Server) registerOAuthServerClient(ctx context.Context, params *OAuthServerClientRegisterParams) (*models.OAuthServerClient, string, error) {
	// Validate all parameters
	if err := params.validate(); err != nil {
		return nil, "", err
	}

	// Set defaults
	grantTypes := params.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code", "refresh_token"}
	}

	db := s.db.WithContext(ctx)

	client := &models.OAuthServerClient{
		ClientID:         generateClientID(),
		RegistrationType: params.RegistrationType,
		ClientName:       storage.NullString(params.ClientName),
		ClientURI:        storage.NullString(params.ClientURI),
		LogoURI:          storage.NullString(params.LogoURI),
	}

	client.SetRedirectURIs(params.RedirectURIs)
	client.SetGrantTypes(grantTypes)

	// Generate client secret for all clients
	plaintextSecret := generateClientSecret()
	hash, err := hashClientSecret(plaintextSecret)
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to hash client secret")
	}
	client.ClientSecretHash = hash

	if err := models.CreateOAuthServerClient(db, client); err != nil {
		return nil, "", errors.Wrap(err, "failed to create OAuth client")
	}

	return client, plaintextSecret, nil
}

// getOAuthServerClient retrieves an OAuth client by client_id
func (s *Server) getOAuthServerClient(ctx context.Context, clientID string) (*models.OAuthServerClient, error) {
	db := s.db.WithContext(ctx)

	client, err := models.FindOAuthServerClientByClientID(db, clientID)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// deleteOAuthServerClient soft-deletes an OAuth client
func (s *Server) deleteOAuthServerClient(ctx context.Context, clientID string) error {
	db := s.db.WithContext(ctx)

	client, err := models.FindOAuthServerClientByClientID(db, clientID)
	if err != nil {
		return err
	}

	// Soft delete by setting deleted_at
	now := time.Now()
	client.DeletedAt = &now

	if err := models.UpdateOAuthServerClient(db, client); err != nil {
		return errors.Wrap(err, "failed to delete OAuth client")
	}

	return nil
}
