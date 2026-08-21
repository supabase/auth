package protocol

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

const emptyListResponse = `{
	"schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
	"totalResults": 0,
	"startIndex": 1,
	"itemsPerPage": 0,
	"Resources": []
}`

func TestNewListResponse(t *testing.T) {
	for _, tc := range []struct {
		name       string
		startIndex int
		total      int
		resources  []string
		expected   string
	}{
		{
			name:       "nil resources marshal to an empty array",
			startIndex: 1,
			resources:  nil,
			expected:   emptyListResponse,
		},
		{
			name:       "empty resources marshal to an empty array",
			startIndex: 1,
			resources:  []string{},
			expected:   emptyListResponse,
		},
		{
			name:       "reports the resources on the page as the page size",
			startIndex: 1,
			total:      2,
			resources:  []string{"a", "b"},
			expected: `{
				"schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
				"totalResults": 2,
				"startIndex": 1,
				"itemsPerPage": 2,
				"Resources": ["a", "b"]
			}`,
		},
		{
			name:       "counts every match, not just the resources on the page",
			startIndex: 3,
			total:      9,
			resources:  []string{"c", "d"},
			expected: `{
				"schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
				"totalResults": 9,
				"startIndex": 3,
				"itemsPerPage": 2,
				"Resources": ["c", "d"]
			}`,
		},
		{
			name:       "reports the total of a page the client asked to skip",
			startIndex: 1,
			total:      5000,
			resources:  []string{},
			expected: `{
				"schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
				"totalResults": 5000,
				"startIndex": 1,
				"itemsPerPage": 0,
				"Resources": []
			}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, err := json.Marshal(NewListResponse(tc.startIndex, tc.total, tc.resources))

			require.NoError(t, err)
			require.JSONEq(t, tc.expected, string(body))
		})
	}
}
