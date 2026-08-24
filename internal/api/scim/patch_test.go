package scim

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/supabase/auth/internal/api/scim/core"
	"github.com/supabase/auth/internal/api/scim/protocol"
)

func ptr[T any](v T) *T { return &v }

func TestApplyUserPatch(t *testing.T) {
	base := func() *core.User {
		return &core.User{
			ID:         "11111111-1111-1111-1111-111111111111",
			UserName:   "bjensen",
			ExternalID: "ext-1",
			Active:     ptr(true),
			Meta:       core.Meta{ResourceType: "User"},
		}
	}

	t.Run("Okta deactivate replaces active with no path", func(t *testing.T) {
		got, err := applyUserPatch(base(), patchOf(t, `{"Operations":[{"op":"replace","value":{"active":false}}]}`))
		require.NoError(t, err)
		require.Equal(t, ptr(false), got.Active)
		require.Equal(t, "bjensen", got.UserName, "attributes not named are left untouched")
	})

	t.Run("replace a simple attribute by path", func(t *testing.T) {
		got, err := applyUserPatch(base(), patchOf(t, `{"Operations":[{"op":"replace","path":"userName","value":"bj2"}]}`))
		require.NoError(t, err)
		require.Equal(t, "bj2", got.UserName)
	})

	t.Run("replace a sub-attribute by path", func(t *testing.T) {
		got, err := applyUserPatch(base(), patchOf(t, `{"Operations":[{"op":"replace","path":"name.familyName","value":"Jensen"}]}`))
		require.NoError(t, err)
		require.Equal(t, "Jensen", got.Name.FamilyName)
	})

	t.Run("add sets an attribute", func(t *testing.T) {
		got, err := applyUserPatch(base(), patchOf(t, `{"Operations":[{"op":"add","path":"externalId","value":"ext-2"}]}`))
		require.NoError(t, err)
		require.Equal(t, "ext-2", got.ExternalID)
	})

	t.Run("remove clears an attribute", func(t *testing.T) {
		got, err := applyUserPatch(base(), patchOf(t, `{"Operations":[{"op":"remove","path":"externalId"}]}`))
		require.NoError(t, err)
		require.Empty(t, got.ExternalID)
	})

	t.Run("path names an attribute without regard to case", func(t *testing.T) {
		got, err := applyUserPatch(base(), patchOf(t, `{"Operations":[{"op":"replace","path":"ACTIVE","value":false}]}`))
		require.NoError(t, err)
		require.Equal(t, ptr(false), got.Active)
	})

	t.Run("operations apply in order", func(t *testing.T) {
		got, err := applyUserPatch(base(), patchOf(t, `{"Operations":[
			{"op":"replace","path":"userName","value":"first"},
			{"op":"replace","path":"userName","value":"second"}
		]}`))
		require.NoError(t, err)
		require.Equal(t, "second", got.UserName)
	})

	t.Run("rejects a patch that removes userName", func(t *testing.T) {
		_, err := applyUserPatch(base(), patchOf(t, `{"Operations":[{"op":"remove","path":"userName"}]}`))
		require.ErrorIs(t, err, protocol.ErrInvalidValue(""), "userName is required and must not be removed")
	})

	t.Run("rejects a patch that empties userName", func(t *testing.T) {
		_, err := applyUserPatch(base(), patchOf(t, `{"Operations":[{"op":"replace","path":"userName","value":""}]}`))
		require.ErrorIs(t, err, protocol.ErrInvalidValue(""), "userName must not be emptied")
	})

	t.Run("drops an attribute core.User does not model", func(t *testing.T) {
		got, err := applyUserPatch(base(), patchOf(t, `{"Operations":[{"op":"add","path":"displayName","value":"BJ"}]}`))
		require.NoError(t, err)

		encoded, err := json.Marshal(got)
		require.NoError(t, err)
		require.NotContains(t, string(encoded), "displayName", "an unmodeled attribute is not retained")
	})

	t.Run("id and meta are the server's and survive a patch", func(t *testing.T) {
		original := base()
		got, err := applyUserPatch(original, patchOf(t, `{"Operations":[{"op":"replace","value":{"id":"evil","userName":"x"}}]}`))
		require.NoError(t, err)
		require.Equal(t, original.ID, got.ID)
		require.Equal(t, original.Meta, got.Meta)
	})

	t.Run("does not mutate the resource it was given", func(t *testing.T) {
		original := base()
		_, err := applyUserPatch(original, patchOf(t, `{"Operations":[{"op":"replace","value":{"active":false}}]}`))
		require.NoError(t, err)
		require.Equal(t, ptr(true), original.Active, "the input is left unchanged")
	})
}
