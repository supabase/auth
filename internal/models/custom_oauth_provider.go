package models

import (
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"time"

	"github.com/gofrs/uuid"
	"github.com/lib/pq"
	"github.com/pkg/errors"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/crypto"
	"github.com/supabase/auth/internal/storage"
)

// ProviderType represents the type of OAuth provider
type ProviderType string

const (
	ProviderTypeOAuth2 ProviderType = "oauth2"
	ProviderTypeOIDC   ProviderType = "oidc"
)

// CustomOAuthProvider represents a custom OAuth2 or OIDC provider configuration
type CustomOAuthProvider struct {
	ID           uuid.UUID    `db:"id" json:"id"`
	ProviderType ProviderType `db:"provider_type" json:"provider_type"`

	// Common fields for both OAuth2 and OIDC
	Identifier string `db:"identifier" json:"identifier"`
	Name       string `db:"name" json:"name"`
	ClientID   string `db:"client_id" json:"client_id"`
	// TODO: Implement client_secret encryption
	//
	// Current state: Client secrets are stored as plaintext in the database.
	//
	// Security concern: OAuth client secrets are sensitive credentials that should be
	// encrypted at rest. If the database is compromised, attackers could use these
	// secrets to impersonate the auth server to external OAuth providers.
	//
	// What's needed:
	// 1. Choose encryption approach:
	//    - Application-level encryption using a master key (stored in env/secrets manager)
	//    - Database-level encryption (PostgreSQL pgcrypto extension)
	// 2. Implement encryption when storing (CreateCustomOAuthProvider, UpdateCustomOAuthProvider)
	// 3. Implement decryption when retrieving (all Find* functions)
	// 4. Consider key rotation strategy
	ClientSecret        string                   `db:"client_secret" json:"-"` // Never expose in JSON
	AcceptableClientIDs StringSlice              `db:"acceptable_client_ids" json:"acceptable_client_ids"`
	Scopes              StringSlice              `db:"scopes" json:"scopes"`
	PKCEEnabled         bool                     `db:"pkce_enabled" json:"pkce_enabled"`
	AttributeMapping    OAuthAttributeMapping    `db:"attribute_mapping" json:"attribute_mapping"`
	AuthorizationParams OAuthAuthorizationParams `db:"authorization_params" json:"authorization_params"`
	Enabled             bool                     `db:"enabled" json:"enabled"`
	EmailOptional       bool                     `db:"email_optional" json:"email_optional"`

	// OIDC-specific fields (null for OAuth2 providers)
	Issuer            *string        `db:"issuer" json:"issuer,omitempty"`
	DiscoveryURL      *string        `db:"discovery_url" json:"discovery_url,omitempty"`
	SkipNonceCheck    bool           `db:"skip_nonce_check" json:"skip_nonce_check"`
	CachedDiscovery   *OIDCDiscovery `db:"cached_discovery" json:"cached_discovery,omitempty"`
	DiscoveryCachedAt *time.Time     `db:"discovery_cached_at" json:"discovery_cached_at,omitempty"`

	// OAuth2-specific fields (null for OIDC providers)
	AuthorizationURL *string `db:"authorization_url" json:"authorization_url,omitempty"`
	TokenURL         *string `db:"token_url" json:"token_url,omitempty"`
	UserinfoURL      *string `db:"userinfo_url" json:"userinfo_url,omitempty"`
	JwksURI          *string `db:"jwks_uri" json:"jwks_uri,omitempty"`

	// Timestamps
	CreatedAt time.Time `db:"created_at" json:"created_at"`
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`
}

func (p CustomOAuthProvider) TableName() string {
	return "custom_oauth_providers"
}

// SetClientSecret encrypts and stores the client secret using the configured
// database encryption settings. If encryption is disabled, the secret is
// stored in plaintext (temporary fallback for now)
func (p *CustomOAuthProvider) SetClientSecret(secret string, dbEncryption conf.DatabaseEncryptionConfiguration) error {
	if !dbEncryption.Encrypt {
		// Fallback: store in plaintext when encryption is not enabled.
		p.ClientSecret = secret
		return nil
	}

	if dbEncryption.EncryptionKeyID == "" || dbEncryption.EncryptionKey == "" {
		return errors.New("database encryption key configuration is invalid")
	}

	es, err := crypto.NewEncryptedString(p.ID.String(), []byte(secret), dbEncryption.EncryptionKeyID, dbEncryption.EncryptionKey)
	if err != nil {
		return errors.Wrap(err, "error encrypting custom OAuth client secret")
	}

	p.ClientSecret = es.String()
	return nil
}

// GetClientSecret decrypts and returns the client secret using the configured
// database decryption keys. It expects the client secret to be stored in
// encrypted form when encryption is enabled, but will also handle plaintext
// secrets (for deployments where encryption is not yet configured).
func (p *CustomOAuthProvider) GetClientSecret(dbEncryption conf.DatabaseEncryptionConfiguration) (string, error) {
	if p.ClientSecret == "" {
		return "", nil
	}

	es := crypto.ParseEncryptedString(p.ClientSecret)
	if es == nil {
		// Not an encrypted string – treat as plaintext.
		return p.ClientSecret, nil
	}

	if dbEncryption.DecryptionKeys == nil {
		return "", errors.New("database decryption keys not configured")
	}

	bytes, err := es.Decrypt(p.ID.String(), dbEncryption.DecryptionKeys)
	if err != nil {
		return "", errors.Wrap(err, "error decrypting custom OAuth client secret")
	}

	return string(bytes), nil
}

// IsOIDC returns true if this is an OIDC provider
func (p *CustomOAuthProvider) IsOIDC() bool {
	return p.ProviderType == ProviderTypeOIDC
}

// IsOAuth2 returns true if this is an OAuth2 provider
func (p *CustomOAuthProvider) IsOAuth2() bool {
	return p.ProviderType == ProviderTypeOAuth2
}

// GetProviderName returns the provider identifier (which already includes "custom:" prefix)
func (p *CustomOAuthProvider) GetProviderName() string {
	return p.Identifier
}

// GetDiscoveryURL returns the discovery URL for OIDC providers
// If discovery_url is set, use that; otherwise construct from issuer
func (p *CustomOAuthProvider) GetDiscoveryURL() string {
	if !p.IsOIDC() || p.Issuer == nil {
		return ""
	}

	if p.DiscoveryURL != nil && *p.DiscoveryURL != "" {
		return *p.DiscoveryURL
	}

	return *p.Issuer + "/.well-known/openid-configuration"
}

// StringSlice handles PostgreSQL text[] type
type StringSlice []string

func (s *StringSlice) Scan(src interface{}) error {
	if src == nil {
		*s = []string{}
		return nil
	}

	// Create a temporary []string slice and scan into it
	var tmp []string
	if err := pq.Array(&tmp).Scan(src); err != nil {
		return errors.Wrap(err, "error scanning string slice")
	}

	// Convert to StringSlice
	*s = StringSlice(tmp)
	return nil
}

func (s StringSlice) Value() (driver.Value, error) {
	if s == nil || len(s) == 0 {
		return "{}", nil
	}

	// Convert StringSlice to []string and use pq.Array
	// This will handle escaping and formatting correctly
	tmp := []string(s)
	return pq.Array(tmp).Value()
}

// OAuthAttributeMapping defines how to map provider attributes to user fields
type OAuthAttributeMapping map[string]interface{}

func (m *OAuthAttributeMapping) Scan(src interface{}) error {
	if src == nil {
		*m = make(OAuthAttributeMapping)
		return nil
	}

	b, ok := src.([]byte)
	if !ok {
		str, ok := src.(string)
		if !ok {
			return errors.New("scan source was not []byte or string")
		}
		b = []byte(str)
	}

	if err := json.Unmarshal(b, m); err != nil {
		return errors.Wrap(err, "error unmarshaling attribute mapping")
	}

	return nil
}

func (m OAuthAttributeMapping) Value() (driver.Value, error) {
	if m == nil {
		return "{}", nil
	}

	b, err := json.Marshal(m)
	if err != nil {
		return nil, errors.Wrap(err, "error marshaling attribute mapping")
	}

	return string(b), nil
}

// OAuthAuthorizationParams holds additional parameters for authorization requests
type OAuthAuthorizationParams map[string]interface{}

func (p *OAuthAuthorizationParams) Scan(src interface{}) error {
	if src == nil {
		*p = make(OAuthAuthorizationParams)
		return nil
	}

	b, ok := src.([]byte)
	if !ok {
		str, ok := src.(string)
		if !ok {
			return errors.New("scan source was not []byte or string")
		}
		b = []byte(str)
	}

	if err := json.Unmarshal(b, p); err != nil {
		return errors.Wrap(err, "error unmarshaling authorization params")
	}

	return nil
}

func (p OAuthAuthorizationParams) Value() (driver.Value, error) {
	if p == nil {
		return "{}", nil
	}

	b, err := json.Marshal(p)
	if err != nil {
		return nil, errors.Wrap(err, "error marshaling authorization params")
	}

	return string(b), nil
}

// OIDCDiscovery represents cached OIDC discovery document
type OIDCDiscovery struct {
	Issuer                 string   `json:"issuer"`
	AuthorizationEndpoint  string   `json:"authorization_endpoint"`
	TokenEndpoint          string   `json:"token_endpoint"`
	UserinfoEndpoint       string   `json:"userinfo_endpoint,omitempty"`
	JwksURI                string   `json:"jwks_uri"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported []string `json:"response_types_supported,omitempty"`
	GrantTypesSupported    []string `json:"grant_types_supported,omitempty"`
	SubjectTypesSupported  []string `json:"subject_types_supported,omitempty"`
}

func (d *OIDCDiscovery) Scan(src interface{}) error {
	if src == nil {
		return nil
	}

	b, ok := src.([]byte)
	if !ok {
		str, ok := src.(string)
		if !ok {
			return errors.New("scan source was not []byte or string")
		}
		b = []byte(str)
	}

	if err := json.Unmarshal(b, d); err != nil {
		return errors.Wrap(err, "error unmarshaling OIDC discovery")
	}

	return nil
}

func (d *OIDCDiscovery) Value() (driver.Value, error) {
	if d == nil {
		return nil, nil
	}

	b, err := json.Marshal(d)
	if err != nil {
		return nil, errors.Wrap(err, "error marshaling OIDC discovery")
	}

	return string(b), nil
}

// CRUD operations for CustomOAuthProvider

// FindCustomOAuthProviderByID finds a custom OAuth provider by ID
func FindCustomOAuthProviderByID(tx *storage.Connection, id uuid.UUID) (*CustomOAuthProvider, error) {
	var provider CustomOAuthProvider

	if err := tx.Q().Where("id = ?", id).First(&provider); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, CustomOAuthProviderNotFoundError{}
		}
		return nil, errors.Wrap(err, "error finding custom OAuth provider by ID")
	}

	return &provider, nil
}

// FindCustomOAuthProviderByIdentifier finds a custom OAuth provider by identifier
func FindCustomOAuthProviderByIdentifier(tx *storage.Connection, identifier string) (*CustomOAuthProvider, error) {
	var provider CustomOAuthProvider

	if err := tx.Q().Where("identifier = ?", identifier).First(&provider); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, CustomOAuthProviderNotFoundError{}
		}
		return nil, errors.Wrap(err, "error finding custom OAuth provider by identifier")
	}

	return &provider, nil
}

// FindAllCustomOAuthProviders finds all custom OAuth providers
func FindAllCustomOAuthProviders(tx *storage.Connection) ([]*CustomOAuthProvider, error) {
	var providers []*CustomOAuthProvider

	if err := tx.Q().Order("created_at desc").All(&providers); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return []*CustomOAuthProvider{}, nil
		}
		return nil, errors.Wrap(err, "error finding all custom OAuth providers")
	}

	return providers, nil
}

// FindAllCustomOAuthProvidersByType finds all custom OAuth providers of a specific type
func FindAllCustomOAuthProvidersByType(tx *storage.Connection, providerType ProviderType) ([]*CustomOAuthProvider, error) {
	var providers []*CustomOAuthProvider

	if err := tx.Q().Where("provider_type = ?", providerType).Order("created_at desc").All(&providers); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return []*CustomOAuthProvider{}, nil
		}
		return nil, errors.Wrap(err, "error finding custom OAuth providers by type")
	}

	return providers, nil
}

// CountCustomOAuthProviders counts all custom OAuth providers
func CountCustomOAuthProviders(tx *storage.Connection) (int, error) {
	count, err := tx.Q().Count(&CustomOAuthProvider{})
	if err != nil {
		return 0, errors.Wrap(err, "error counting custom OAuth providers")
	}
	return count, nil
}

// CreateCustomOAuthProvider creates a new custom OAuth provider
func CreateCustomOAuthProvider(tx *storage.Connection, provider *CustomOAuthProvider) error {
	if provider.ID == uuid.Nil {
		id, err := uuid.NewV4()
		if err != nil {
			return errors.Wrap(err, "error generating custom OAuth provider ID")
		}
		provider.ID = id
	}

	if err := tx.Create(provider); err != nil {
		return errors.Wrap(err, "error creating custom OAuth provider")
	}

	return nil
}

// UpdateCustomOAuthProvider updates an existing custom OAuth provider
func UpdateCustomOAuthProvider(tx *storage.Connection, provider *CustomOAuthProvider) error {
	if err := tx.Update(provider); err != nil {
		return errors.Wrap(err, "error updating custom OAuth provider")
	}
	return nil
}

// DeleteCustomOAuthProvider deletes a custom OAuth provider
func DeleteCustomOAuthProvider(tx *storage.Connection, id uuid.UUID) error {
	if err := tx.Destroy(&CustomOAuthProvider{ID: id}); err != nil {
		return errors.Wrap(err, "error deleting custom OAuth provider")
	}
	return nil
}
