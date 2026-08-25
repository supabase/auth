package scim

import (
	"context"
	"time"
)

type scimUser struct {
	ID        string    `db:"id"`
	Resource  []byte    `db:"resource"`
	Active    bool      `db:"active"`
	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}

func (u *scimUser) ResourceID() string { return u.ID }

func (u *scimUser) Timestamps() (created, updated time.Time) {
	return u.CreatedAt, u.UpdatedAt
}

type scimToken struct {
	ID            string `db:"id"`
	SSOProviderID string `db:"sso_provider_id"`
}

// TODO:: Replace with https://github.com/supabase/auth/pull/2677
type tenantKey struct{}

func withTenant(ctx context.Context, tenant string) context.Context {
	return context.WithValue(ctx, tenantKey{}, tenant)
}

func tenantFrom(ctx context.Context) (string, bool) {
	tenant, ok := ctx.Value(tenantKey{}).(string)
	return tenant, ok && tenant != ""
}
