package scim

import "context"

// Tenants resolves the credential on a request to the tenant it may act for.
// An unknown, malformed, or expired credential is ErrNotFound; anything else is
// a failure to answer the question rather than an answer of no.
type Tenants interface {
	Lookup(ctx context.Context, credential string) (tenant string, err error)
}
