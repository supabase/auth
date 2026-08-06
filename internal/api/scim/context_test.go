package scim

import (
	"context"
	"fmt"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/models"
)

func TestKey(t *testing.T) {
	key := NewKey[*models.SSOProvider]("sso_provider")

	t.Run("round trips a typed value", func(t *testing.T) {
		provider := &models.SSOProvider{ID: uuid.Must(uuid.NewV4())}

		ctx := key.With(context.Background(), provider)

		require.Equal(t, provider, key.From(ctx))
	})

	t.Run("returns the zero value when absent", func(t *testing.T) {
		require.Nil(t, key.From(context.Background()))
	})

	t.Run("keys of different types do not collide", func(t *testing.T) {
		other := NewKey[string]("sso_provider")

		ctx := other.With(context.Background(), "not a provider")

		require.Nil(t, key.From(ctx))
		require.Equal(t, "not a provider", other.From(ctx))
	})

	t.Run("keys of the same type and name share a slot", func(t *testing.T) {
		provider := &models.SSOProvider{ID: uuid.Must(uuid.NewV4())}

		ctx := NewKey[*models.SSOProvider]("sso_provider").With(context.Background(), provider)

		require.Equal(t, provider, key.From(ctx))
	})

	t.Run("keys of the same type but a different name do not collide", func(t *testing.T) {
		first, second := NewKey[string]("first"), NewKey[string]("second")

		ctx := first.With(context.Background(), "one")
		ctx = second.With(ctx, "two")

		require.Equal(t, "one", first.From(ctx))
		require.Equal(t, "two", second.From(ctx))
	})

	t.Run("names the key when a context is printed", func(t *testing.T) {
		ctx := NewKey[string]("first").With(context.Background(), "one")

		require.Contains(t, fmt.Sprint(ctx), "gotrue scim context key first")
	})
}
