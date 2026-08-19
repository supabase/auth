package core

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestKindLocation(t *testing.T) {
	baseURL := "http://localhost:9999/scim/v2"

	t.Run("locates the collection under the base URL", func(t *testing.T) {
		require.Equal(t, baseURL+"/Users", KindUser.Location(baseURL))
	})

	t.Run("does not double the separator when the base URL ends in a slash", func(t *testing.T) {
		require.Equal(t, baseURL+"/Users", KindUser.Location(baseURL+"/"))
	})
}
