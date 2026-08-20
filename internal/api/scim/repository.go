package scim

import (
	"context"
	"errors"
	"maps"
	"slices"
	"sync"

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

type MemoryRepository[T any] struct {
	mu       sync.RWMutex
	byTenant map[string]map[string]T
	idOf     func(T) string
}

func NewMemoryRepository[T any](idOf func(T) string) *MemoryRepository[T] {
	return &MemoryRepository[T]{
		byTenant: make(map[string]map[string]T),
		idOf:     idOf,
	}
}

func (r *MemoryRepository[T]) Put(tenant string, item T) {
	r.mu.Lock()
	defer r.mu.Unlock()

	items, ok := r.byTenant[tenant]
	if !ok {
		items = make(map[string]T)
		r.byTenant[tenant] = items
	}
	items[r.idOf(item)] = item
}

func (r *MemoryRepository[T]) Get(ctx context.Context, tenant, id string) (T, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if item, ok := r.byTenant[tenant][id]; ok {
		return item, nil
	}

	var zero T
	return zero, ErrNotFound
}

func (r *MemoryRepository[T]) List(ctx context.Context, tenant string, count, offset int) ([]T, int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	items := r.byTenant[tenant]
	total := len(items)
	if count <= 0 {
		return nil, total, nil
	}

	if offset < 0 {
		offset = 0
	}
	if offset >= total {
		return nil, total, nil
	}

	ids := slices.Sorted(maps.Keys(items))
	end := min(offset+count, total)
	page := make([]T, 0, end-offset)
	for _, id := range ids[offset:end] {
		page = append(page, items[id])
	}
	return page, total, nil
}
