package models

import (
	"context"
	"time"

	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"github.com/supabase/auth/internal/crypto"
	"github.com/supabase/auth/internal/storage"
	"golang.org/x/crypto/bcrypt"
)

// SCIMProvider represents a SCIM provider configuration for enterprise customer isolation
type SCIMProvider struct {
	ID           uuid.UUID `json:"id" db:"id"`
	Name         string    `json:"name" db:"name"`
	PasswordHash string    `json:"-" db:"password_hash"`
	Audience     string    `json:"audience,omitempty" db:"audience"`

	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt time.Time  `json:"updated_at" db:"updated_at"`
	DeletedAt *time.Time `json:"deleted_at,omitempty" db:"deleted_at"`
}

// TableName returns the database table name for SCIMProvider
func (SCIMProvider) TableName() string {
	return "scim_providers"
}

// NewSCIMProvider creates a new SCIM provider with a hashed token
func NewSCIMProvider(name, token, audience string) (*SCIMProvider, error) {
	if name == "" {
		return nil, errors.New("provider name is required")
	}
	if token == "" {
		return nil, errors.New("provider token is required")
	}

	id, err := uuid.NewV4()
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate provider ID")
	}

	// Hash the token using crypto package
	hash, err := crypto.GenerateFromPassword(context.Background(), token)
	if err != nil {
		return nil, errors.Wrap(err, "failed to hash provider token")
	}

	now := time.Now()
	return &SCIMProvider{
		ID:           id,
		Name:         name,
		PasswordHash: hash,
		Audience:     audience,
		CreatedAt:    now,
		UpdatedAt:    now,
	}, nil
}

// Authenticate verifies a token against the provider's stored hash
func (p *SCIMProvider) Authenticate(token string) error {
	if p.DeletedAt != nil {
		return errors.New("provider has been deleted")
	}

	err := bcrypt.CompareHashAndPassword([]byte(p.PasswordHash), []byte(token))
	if err != nil {
		return errors.New("invalid token")
	}
	return nil
}

// UpdateToken updates the provider's token hash
func (p *SCIMProvider) UpdateToken(tx *storage.Connection, newToken string) error {
	hash, err := crypto.GenerateFromPassword(context.Background(), newToken)
	if err != nil {
		return errors.Wrap(err, "failed to hash new token")
	}

	p.PasswordHash = hash
	p.UpdatedAt = time.Now()

	return tx.UpdateOnly(p, "password_hash", "updated_at")
}

// SoftDelete marks the provider as deleted
func (p *SCIMProvider) SoftDelete(tx *storage.Connection) error {
	now := time.Now()
	p.DeletedAt = &now
	p.UpdatedAt = now

	return tx.UpdateOnly(p, "deleted_at", "updated_at")
}

// SCIMProviderNotFoundError is returned when a SCIM provider is not found
type SCIMProviderNotFoundError struct{}

func (e SCIMProviderNotFoundError) Error() string {
	return "SCIM provider not found"
}

// FindSCIMProviderByID finds a provider by ID
func FindSCIMProviderByID(conn *storage.Connection, id uuid.UUID) (*SCIMProvider, error) {
	var provider SCIMProvider
	err := conn.Q().Where("id = ? AND deleted_at IS NULL", id).First(&provider)
	if err != nil {
		return nil, SCIMProviderNotFoundError{}
	}
	return &provider, nil
}

// FindSCIMProviderByName finds a provider by name
func FindSCIMProviderByName(conn *storage.Connection, name string) (*SCIMProvider, error) {
	var provider SCIMProvider
	err := conn.Q().Where("name = ? AND deleted_at IS NULL", name).First(&provider)
	if err != nil {
		return nil, SCIMProviderNotFoundError{}
	}
	return &provider, nil
}

// FindSCIMProviderByToken finds a provider by verifying the token against all active providers
// This is less efficient but necessary for token-based authentication
func FindSCIMProviderByToken(conn *storage.Connection, token string) (*SCIMProvider, error) {
	var providers []*SCIMProvider
	err := conn.Q().Where("deleted_at IS NULL").All(&providers)
	if err != nil {
		return nil, errors.Wrap(err, "failed to query providers")
	}

	for _, provider := range providers {
		if provider.Authenticate(token) == nil {
			return provider, nil
		}
	}

	return nil, errors.New("no provider found with matching token")
}

// FindAllSCIMProviders returns all non-deleted providers
func FindAllSCIMProviders(conn *storage.Connection, page, perPage uint64) ([]*SCIMProvider, error) {
	var providers []*SCIMProvider

	q := conn.Q().Where("deleted_at IS NULL").Order("created_at DESC")

	if page > 0 && perPage > 0 {
		q = q.Paginate(int(page), int(perPage))
	}

	err := q.All(&providers)
	if err != nil {
		return nil, errors.Wrap(err, "failed to query providers")
	}

	return providers, nil
}

// CountSCIMProviders returns the total count of non-deleted providers
func CountSCIMProviders(conn *storage.Connection) (int, error) {
	return conn.Q().Where("deleted_at IS NULL").Count(&SCIMProvider{})
}
