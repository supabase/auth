package scim

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api/scim/core"
	"github.com/supabase/auth/internal/api/scim/protocol"
)

const tenant = "8a2f1c34-0000-0000-0000-000000000000"

// seedUsers fills a store with users that deliberately share a userName and a
// created timestamp. No database would allow that, which is the point: it is
// the degenerate case MemoryStore has to order anyway.
func seedUsers(t *testing.T, count int) *MemoryStore[*core.User] {
	t.Helper()

	store := NewMemoryUserStore()
	created := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

	for i := range count {
		store.Put(tenant, &core.User{
			ID:       strconv.Itoa(i),
			UserName: "duplicate",
			Meta:     core.Meta{Created: created},
		})
	}
	return store
}

// The guarantees every store makes are in storeContract. These are the ones
// only MemoryStore can be asked about.
func TestMemoryStore(t *testing.T) {
	t.Run("orders a tenant's resources without regard to another tenant's", func(t *testing.T) {
		store := seedUsers(t, 3)
		store.Put("other-tenant", &core.User{ID: "999"})

		users, total, err := store.For(tenant).List(context.Background(), &protocol.SearchRequest{
			StartIndex: 1, Count: 10,
		})

		require.NoError(t, err)
		assert.Equal(t, 3, total)
		assert.Len(t, users, 3)
	})

	t.Run("orders resources that tie on every sortable attribute", func(t *testing.T) {
		store := seedUsers(t, 5)

		users, _, err := store.For(tenant).List(context.Background(), &protocol.SearchRequest{
			StartIndex: 1, Count: 5, SortBy: "userName",
		})

		require.NoError(t, err)
		assert.Equal(t, []string{"0", "1", "2", "3", "4"}, idsOf(users),
			"a userName shared by every resource leaves only the id to order by")
	})

	t.Run("reports no resource of an unknown id", func(t *testing.T) {
		_, err := seedUsers(t, 3).For(tenant).Get(context.Background(), "nope")

		require.ErrorIs(t, err, ErrNotFound)
	})
}
