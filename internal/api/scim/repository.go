package scim

import (
	"context"
	"errors"

	"github.com/supabase/auth/internal/api/scim/core"
	"github.com/supabase/auth/internal/storage"
)

var ErrNotFound = errors.New("scim: resource not found")

type Repository[T any] interface {
	Get(ctx context.Context, tenant, id string) (T, error)
	List(ctx context.Context, tenant string, count, offset int) (items []T, total int, err error)
}

type UserRepository = Repository[*core.User]

func NewUserRepository(db *storage.Connection) *MemoryRepository[*core.User] {
	return NewMemoryRepository(func(u *core.User) string { return u.ID })
}
