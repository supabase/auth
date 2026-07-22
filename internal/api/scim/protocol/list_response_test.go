package protocol

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/supabase/auth/internal/api/scim/fixtures"
)

func TestNewListResponse(t *testing.T) {
	for _, tc := range []struct {
		name      string
		resources []string
		expected  string
	}{
		{
			name:      "nil resources marshal to an empty array",
			resources: nil,
			expected:  fixtures.EmptyListResponse,
		},
		{
			name:      "empty resources marshal to an empty array",
			resources: []string{},
			expected:  fixtures.EmptyListResponse,
		},
		{
			name:      "populated resources are counted",
			resources: []string{"a", "b"},
			expected: `{
				"schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
				"totalResults": 2,
				"startIndex": 1,
				"itemsPerPage": 2,
				"Resources": ["a", "b"]
			}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(NewListResponse(tc.resources))
			require.NoError(t, err)
			require.JSONEq(t, tc.expected, string(b))
		})
	}
}
