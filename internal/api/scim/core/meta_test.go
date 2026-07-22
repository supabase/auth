package core

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api/scim/fixtures"
)

func TestMeta(t *testing.T) {
	t.Run("serializes to JSON correctly", func(t *testing.T) {
		body, err := json.Marshal(Meta{
			ResourceType: "ServiceProviderConfig",
			Location:     "http://localhost:9999/scim/v2/ServiceProviderConfig",
		})

		require.NoError(t, err)
		require.JSONEq(t, fixtures.MetaServiceProviderConfig, string(body))
	})
}
