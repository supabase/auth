package models

import (
	"database/sql"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"github.com/supabase/auth/internal/storage"
)

// OAuthServerClient represents an OAuth client application registered with this OAuth server
type OAuthServerClient struct {
	ID               uuid.UUID `json:"-" db:"id"`
	ClientID         string    `json:"client_id" db:"client_id"`
	ClientSecretHash string    `json:"-" db:"client_secret_hash"`
	RegistrationType string    `json:"registration_type" db:"registration_type"`

	RedirectURIs string             `json:"-" db:"redirect_uris"`
	GrantTypes   string             `json:"grant_types" db:"grant_types"`
	ClientName   storage.NullString `json:"client_name" db:"client_name"`
	ClientURI    storage.NullString `json:"client_uri" db:"client_uri"`
	LogoURI      storage.NullString `json:"logo_uri" db:"logo_uri"`
	CreatedAt    time.Time          `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time          `json:"updated_at" db:"updated_at"`
	DeletedAt    *time.Time         `json:"deleted_at,omitempty" db:"deleted_at"`
}

// TableName returns the table name for the OAuthServerClient model
func (OAuthServerClient) TableName() string {
	return "oauth_clients"
}

// BeforeSave is invoked before the OAuth client is saved to the database
func (c *OAuthServerClient) BeforeSave(tx *pop.Connection) error {
	c.UpdatedAt = time.Now()
	return nil
}

// Validate performs basic validation on the OAuth client
func (c *OAuthServerClient) Validate() error {
	if c.ClientID == "" {
		return fmt.Errorf("client_id is required")
	}

	if c.RegistrationType != "dynamic" && c.RegistrationType != "manual" {
		return fmt.Errorf("registration_type must be 'dynamic' or 'manual'")
	}

	if c.RedirectURIs == "" {
		return fmt.Errorf("at least one redirect_uri is required")
	}

	return nil
}

// GetRedirectURIs returns the redirect URIs as a slice
func (c *OAuthServerClient) GetRedirectURIs() []string {
	if c.RedirectURIs == "" {
		return []string{}
	}
	return strings.Split(c.RedirectURIs, ",")
}

// SetRedirectURIs sets the redirect URIs from a slice
func (c *OAuthServerClient) SetRedirectURIs(uris []string) {
	c.RedirectURIs = strings.Join(uris, ",")
}

// GetGrantTypes returns the grant types as a slice
func (c *OAuthServerClient) GetGrantTypes() []string {
	if c.GrantTypes == "" {
		return []string{}
	}
	return strings.Split(c.GrantTypes, ",")
}

// SetGrantTypes sets the grant types from a slice
func (c *OAuthServerClient) SetGrantTypes(types []string) {
	c.GrantTypes = strings.Join(types, ",")
}

// validateRedirectURI validates a single redirect URI according to OAuth 2.1 spec
func validateRedirectURI(uri string) error {
	if uri == "" {
		return fmt.Errorf("redirect URI cannot be empty")
	}

	parsedURL, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("invalid URL format: %v", err)
	}

	if parsedURL.Scheme == "" {
		return fmt.Errorf("redirect URI must be absolute (include scheme)")
	}

	if parsedURL.Fragment != "" {
		return fmt.Errorf("redirect URI must not contain fragment")
	}

	// Allow localhost for development, otherwise require HTTPS
	if parsedURL.Scheme == "http" {
		if parsedURL.Hostname() != "localhost" && parsedURL.Hostname() != "127.0.0.1" {
			return fmt.Errorf("redirect URI must use HTTPS except for localhost")
		}
	} else if parsedURL.Scheme != "https" {
		return fmt.Errorf("redirect URI must use HTTPS or HTTP for localhost")
	}

	return nil
}

// Error types for OAuth client operations
type OAuthServerClientNotFoundError struct{}

func (e OAuthServerClientNotFoundError) Error() string {
	return "OAuth client not found"
}

type InvalidRedirectURIError struct {
	URI string
}

func (e InvalidRedirectURIError) Error() string {
	return fmt.Sprintf("invalid redirect URI: %s", e.URI)
}

// Query functions for OAuth clients

// FindOAuthServerClientByID finds an OAuth client by ID
func FindOAuthServerClientByID(tx *storage.Connection, id uuid.UUID) (*OAuthServerClient, error) {
	client := &OAuthServerClient{}
	if err := tx.Q().Where("id = ? AND deleted_at IS NULL", id).First(client); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, OAuthServerClientNotFoundError{}
		}
		return nil, errors.Wrap(err, "error finding OAuth client")
	}
	return client, nil
}

// FindOAuthServerClientByClientID finds an OAuth client by client_id
func FindOAuthServerClientByClientID(tx *storage.Connection, clientID string) (*OAuthServerClient, error) {
	client := &OAuthServerClient{}
	if err := tx.Q().Where("client_id = ? AND deleted_at IS NULL", clientID).First(client); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, OAuthServerClientNotFoundError{}
		}
		return nil, errors.Wrap(err, "error finding OAuth client")
	}
	return client, nil
}

// CreateOAuthServerClient creates a new OAuth client in the database
func CreateOAuthServerClient(tx *storage.Connection, client *OAuthServerClient) error {
	if err := client.Validate(); err != nil {
		return err
	}

	if client.ID == uuid.Nil {
		client.ID = uuid.Must(uuid.NewV4())
	}

	now := time.Now()
	client.CreatedAt = now
	client.UpdatedAt = now

	return tx.Create(client)
}

// UpdateOAuthServerClient updates an existing OAuth client in the database
func UpdateOAuthServerClient(tx *storage.Connection, client *OAuthServerClient) error {
	if err := client.Validate(); err != nil {
		return err
	}

	client.UpdatedAt = time.Now()
	return tx.Update(client)
}
