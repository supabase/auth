package scim

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/supabase/auth/internal/api/scim/core"
	"github.com/supabase/auth/internal/storage"
)

const getUser = `SELECT id, resource, active, created_at, updated_at FROM scim_users
	WHERE sso_provider_id = ? AND deleted_at IS NULL AND id = ?`

type userRepository struct {
	db      *storage.Connection
	baseURL string
}

func (r *userRepository) Get(ctx context.Context, id string) (*core.User, error) {
	var rows []scimUser

	if err := r.db.WithContext(ctx).RawQuery(getUser, r.tenant(ctx), id).All(&rows); err != nil {
		return nil, fmt.Errorf("scim: reading user: %w", err)
	}

	if len(rows) == 0 {
		return nil, ErrNotFound
	}
	return r.mapFrom(&rows[0])
}

func (r *userRepository) mapFrom(row *scimUser) (*core.User, error) {
	user := new(core.User)
	if err := json.Unmarshal(row.Resource, user); err != nil {
		return nil, fmt.Errorf("scim: decoding stored user %s: %w", row.ID, err)
	}

	user.ID = row.ID
	user.Active = &row.Active
	user.Meta = core.NewMeta(r.baseURL, core.KindUser).For(row)

	if len(user.Schemas) == 0 {
		user.Schemas = []core.SchemaURI{core.SchemaUser}
	}
	return user, nil
}

func (r *userRepository) tenant(ctx context.Context) string {
	tenant, _ := tenantFrom(ctx)
	return tenant
}
