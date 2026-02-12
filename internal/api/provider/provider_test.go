package provider

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestClaimsUpdatedAt_Unmarshal(t *testing.T) {
	t.Run("numeric date seconds", func(t *testing.T) {
		var c Claims
		require.NoError(t, json.Unmarshal([]byte(`{"updated_at": 1700000000}`), &c))
		require.NotNil(t, c.UpdatedAt)
		require.Equal(t, int64(1700000000), time.Time(*c.UpdatedAt).Unix())
	})

	t.Run("rfc3339 string", func(t *testing.T) {
		var c Claims
		require.NoError(t, json.Unmarshal([]byte(`{"updated_at": "2024-01-02T03:04:05Z"}`), &c))
		require.NotNil(t, c.UpdatedAt)
		require.Equal(t, int64(1704164645), time.Time(*c.UpdatedAt).Unix())
	})
}
