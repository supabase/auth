package protocol

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParsePatchOp(t *testing.T) {
	t.Run("Okta deactivate: replace with no path", func(t *testing.T) {
		patch, err := ParsePatchOp([]byte(`{
			"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			"Operations": [{"op": "replace", "value": {"active": false}}]
		}`))
		require.NoError(t, err)
		require.Len(t, patch.Operations, 1)

		op := patch.Operations[0]
		require.Equal(t, PatchReplace, op.Kind())

		_, hasPath, err := op.Target()
		require.NoError(t, err)
		require.False(t, hasPath, "a replace with no path targets the resource itself")
	})

	t.Run("path names a simple attribute", func(t *testing.T) {
		patch, err := ParsePatchOp([]byte(`{"Operations": [{"op": "replace", "path": "active", "value": true}]}`))
		require.NoError(t, err)

		path, hasPath, err := patch.Operations[0].Target()
		require.NoError(t, err)
		require.True(t, hasPath)
		require.Equal(t, AttrPath{Name: "active"}, path)
	})

	t.Run("path names a sub-attribute", func(t *testing.T) {
		patch, err := ParsePatchOp([]byte(`{"Operations": [{"op": "replace", "path": "name.familyName", "value": "Jensen"}]}`))
		require.NoError(t, err)

		path, _, err := patch.Operations[0].Target()
		require.NoError(t, err)
		require.Equal(t, AttrPath{Name: "name", Sub: "familyName"}, path)
	})

	t.Run("op is matched without regard to case", func(t *testing.T) {
		patch, err := ParsePatchOp([]byte(`{"Operations": [{"op": "Replace", "path": "active", "value": true}]}`))
		require.NoError(t, err)
		require.Equal(t, PatchReplace, patch.Operations[0].Kind())
	})

	t.Run("add and remove", func(t *testing.T) {
		patch, err := ParsePatchOp([]byte(`{"Operations": [
			{"op": "add", "path": "active", "value": true},
			{"op": "remove", "path": "nickName"}
		]}`))
		require.NoError(t, err)
		require.Equal(t, PatchAdd, patch.Operations[0].Kind())
		require.Equal(t, PatchRemove, patch.Operations[1].Kind())
	})
}

func TestParsePatchOpRejects(t *testing.T) {
	cases := []struct {
		name string
		body string
		is   *Error
	}{
		{"malformed JSON", `{"Operations": [`, ErrInvalidSyntax("")},
		{"no operations", `{"Operations": []}`, ErrInvalidValue("")},
		{"missing operations", `{"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"]}`, ErrInvalidValue("")},
		{"unknown op", `{"Operations": [{"op": "move", "path": "active"}]}`, ErrInvalidValue("")},
		{"remove without a path", `{"Operations": [{"op": "remove"}]}`, ErrNoTarget("")},
		{"value path is not a supported target", `{"Operations": [{"op": "replace", "path": "emails[type eq \"work\"]", "value": "x"}]}`, ErrInvalidPath("")},
		{"malformed path", `{"Operations": [{"op": "replace", "path": "1bad", "value": "x"}]}`, ErrInvalidPath("")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParsePatchOp([]byte(tc.body))
			require.Error(t, err)
			require.True(t, errors.Is(err, tc.is), "want %v, got %v", tc.is, err)
		})
	}
}
