package scim

import (
	"context"

	"github.com/supabase/auth/internal/api/scim/protocol"
)

type Repository[T any] interface {
	Get(ctx context.Context, id string) (T, error)
	List(ctx context.Context, query *protocol.SearchRequest) (items []T, total int, err error)
	Create(ctx context.Context, item T) (T, error)
	Replace(ctx context.Context, id string, item T) (T, error)
	Patch(ctx context.Context, id string, patch *protocol.PatchOp) (T, error)
	Delete(ctx context.Context, id string) error
}
