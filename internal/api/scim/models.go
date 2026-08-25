package scim

import (
	"context"
	"errors"
)

var ErrNotFound = errors.New("scim: resource not found")

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
