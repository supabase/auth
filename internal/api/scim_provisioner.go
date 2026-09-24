package api

import (
	"context"
	"time"

	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/api/scim"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

type scimProvisioner struct {
	api *API
}

func newSCIMProvisioner(api *API) scim.Provisioner {
	return &scimProvisioner{api: api}
}

func (p *scimProvisioner) CreateUser(ctx context.Context, providerID uuid.UUID, user scim.UserInput) (*models.SCIMUser, error) {
	var row *models.SCIMUser
	err := p.api.db.WithContext(ctx).Transaction(func(tx *storage.Connection) error {
		var terr error
		row, terr = models.CreateSCIMUser(tx, providerID, user.Resource)
		return terr
	})
	return row, err
}

func (p *scimProvisioner) ReplaceUser(ctx context.Context, providerID, id uuid.UUID, user scim.UserInput, updatedAt *time.Time) (*models.SCIMUser, error) {
	var row *models.SCIMUser
	err := p.api.db.WithContext(ctx).Transaction(func(tx *storage.Connection) error {
		var terr error
		row, terr = models.ReplaceSCIMUser(tx, providerID, id, user.Resource, updatedAt)
		return terr
	})
	return row, err
}

func (p *scimProvisioner) DeleteUser(ctx context.Context, providerID, id uuid.UUID) error {
	return p.api.db.WithContext(ctx).Transaction(func(tx *storage.Connection) error {
		return models.DeleteSCIMUser(tx, providerID, id)
	})
}
