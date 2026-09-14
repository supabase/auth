package scim

import (
	"context"

	"github.com/supabase-community/scim-go/pkg/protocol"
)

// Separate from Repository[T] so SAML/SCIM identity-linking sync can sit here later without touching storage.
type Service[T any] interface {
	Get(ctx context.Context, id string) (T, error)
	List(ctx context.Context, query *protocol.SearchRequest) (items []T, total int, err error)
	Create(ctx context.Context, item T) (T, error)
	Replace(ctx context.Context, id string, item T) (T, error)
	Delete(ctx context.Context, id string) error
}
