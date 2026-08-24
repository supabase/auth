package scim

import "context"

type Tenants interface {
	Lookup(ctx context.Context, credential string) (tenant string, err error)
}
