package scim

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api/scim/core"
)

func user(id string) *core.User {
	return &core.User{ID: id, UserName: id + "@example.com"}
}

func TestMemoryRepositoryGet(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryRepository(func(u *core.User) string { return u.ID })
	repo.Put("tenant-a", user("1"))

	t.Run("returns a stored resource", func(t *testing.T) {
		got, err := repo.Get(ctx, "tenant-a", "1")
		require.NoError(t, err)
		require.Equal(t, "1", got.ID)
	})

	t.Run("reports an unknown id as not found", func(t *testing.T) {
		got, err := repo.Get(ctx, "tenant-a", "missing")
		require.Nil(t, got)
		require.True(t, errors.Is(err, ErrNotFound))
	})

	t.Run("does not reach across tenants", func(t *testing.T) {
		got, err := repo.Get(ctx, "tenant-b", "1")
		require.Nil(t, got)
		require.True(t, errors.Is(err, ErrNotFound))
	})
}

func TestMemoryRepositoryList(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryRepository(func(u *core.User) string { return u.ID })
	for _, id := range []string{"3", "1", "2"} {
		repo.Put("tenant-a", user(id))
	}
	repo.Put("tenant-b", user("9"))

	ids := func(users []*core.User) []string {
		out := make([]string, 0, len(users))
		for _, u := range users {
			out = append(out, u.ID)
		}
		return out
	}

	t.Run("returns every resource with the total", func(t *testing.T) {
		users, total, err := repo.List(ctx, "tenant-a", 100, 0)
		require.NoError(t, err)
		require.Equal(t, 3, total)
		require.Equal(t, []string{"1", "2", "3"}, ids(users))
	})

	t.Run("walks the collection in a stable order", func(t *testing.T) {
		first, _, err := repo.List(ctx, "tenant-a", 2, 0)
		require.NoError(t, err)
		second, total, err := repo.List(ctx, "tenant-a", 2, 2)
		require.NoError(t, err)

		require.Equal(t, 3, total)
		require.Equal(t, []string{"1", "2"}, ids(first))
		require.Equal(t, []string{"3"}, ids(second))
	})

	t.Run("scopes the collection to one tenant", func(t *testing.T) {
		users, total, err := repo.List(ctx, "tenant-b", 100, 0)
		require.NoError(t, err)
		require.Equal(t, 1, total)
		require.Equal(t, []string{"9"}, ids(users))
	})
}
