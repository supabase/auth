package scim

import (
	"context"

	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

// Tenants resolves the credential on a request to the tenant it may act for.
// An unknown or malformed credential is ErrNotFound; anything else is a failure
// to answer the question rather than an answer of no.
type Tenants interface {
	Lookup(ctx context.Context, credential string) (tenant string, err error)
}

// ProviderTenants treats the credential as the id of an SSO provider.
//
// TEMPORARY: this is what stands in for a SCIM token. It authenticates nobody,
// so the route it guards also demands admin credentials; both go away when
// tokens land and a TokenTenants replaces this.
type ProviderTenants struct {
	db *storage.Connection
}

func NewProviderTenants(db *storage.Connection) *ProviderTenants {
	return &ProviderTenants{db: db}
}

func (t *ProviderTenants) Lookup(ctx context.Context, credential string) (string, error) {
	id, err := uuid.FromString(credential)
	if err != nil || id == uuid.Nil {
		return "", ErrNotFound
	}

	provider, err := models.FindSSOProviderByID(t.db.WithContext(ctx), id)
	if err != nil {
		if models.IsNotFoundError(err) {
			return "", ErrNotFound
		}
		return "", err
	}

	return provider.ID.String(), nil
}
