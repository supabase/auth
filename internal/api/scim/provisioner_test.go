package scim

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/supabase-community/scim-go/pkg/core"
)

func TestToInput(t *testing.T) {
	t.Run("defaults active to true", func(t *testing.T) {
		input, err := toInput(&core.User{UserName: "alice@example.com"})
		require.NoError(t, err)
		require.Equal(t, "alice@example.com", input.UserName)
		require.True(t, input.Active)
		require.Empty(t, input.Email)
	})

	t.Run("reads active", func(t *testing.T) {
		input, err := toInput(&core.User{UserName: "alice@example.com", Active: new(false)})
		require.NoError(t, err)
		require.False(t, input.Active)
	})

	t.Run("prefers the primary email", func(t *testing.T) {
		input, err := toInput(&core.User{
			UserName: "alice",
			Emails: []core.Email{
				{Value: "work@example.com"},
				{Value: "home@example.com", Primary: new(true)},
			},
		})
		require.NoError(t, err)
		require.Equal(t, "home@example.com", input.Email)
	})

	t.Run("falls back to the first email", func(t *testing.T) {
		input, err := toInput(&core.User{
			UserName: "alice",
			Emails:   []core.Email{{Value: "work@example.com"}, {Value: "home@example.com"}},
		})
		require.NoError(t, err)
		require.Equal(t, "work@example.com", input.Email)
	})

	t.Run("drops id, meta and password from the resource", func(t *testing.T) {
		user := &core.User{UserName: "alice", Password: "secret"}
		user.ID = "abc"
		user.Meta = core.Meta{Version: `W/"1"`}

		input, err := toInput(user)
		require.NoError(t, err)

		resource := map[string]any{}
		require.NoError(t, json.Unmarshal(input.Resource, &resource))
		require.NotContains(t, resource, "id")
		require.NotContains(t, resource, "meta")
		require.NotContains(t, resource, "password")
		require.Equal(t, "alice", resource["userName"])
	})
}
