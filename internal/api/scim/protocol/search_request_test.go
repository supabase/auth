package protocol

import (
	"encoding/json"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api/scim/core"
)

func parseQuery(t *testing.T, query string) (*SearchRequest, error) {
	t.Helper()

	values, err := url.ParseQuery(query)
	require.NoError(t, err)

	return DefaultLimits.ParseSearchRequest(values)
}

func TestParseSearchRequest(t *testing.T) {
	for _, tc := range []struct {
		name  string
		query string
		want  SearchRequest
	}{
		{
			name:  "defaults to the whole first page when the client asks for nothing",
			query: "",
			want:  SearchRequest{StartIndex: 1, Count: DefaultLimits.DefaultCount},
		},
		{
			name:  "honours the window the client asked for",
			query: "startIndex=11&count=10",
			want:  SearchRequest{StartIndex: 11, Count: 10},
		},
		{
			name:  "caps a count larger than the provider is willing to return",
			query: "count=5000",
			want:  SearchRequest{StartIndex: 1, Count: DefaultLimits.MaxCount},
		},
		{
			name:  "reads a start index below the first as the first",
			query: "startIndex=0",
			want:  SearchRequest{StartIndex: 1, Count: DefaultLimits.DefaultCount},
		},
		{
			name:  "reads a negative start index as the first",
			query: "startIndex=-7",
			want:  SearchRequest{StartIndex: 1, Count: DefaultLimits.DefaultCount},
		},
		{
			name:  "reads a negative count as none",
			query: "count=-5",
			want:  SearchRequest{StartIndex: 1, Count: 0},
		},
		{
			name:  "asks for the total alone with a count of none",
			query: "count=0",
			want:  SearchRequest{StartIndex: 1, Count: 0},
		},
		{
			name:  "sorts ascending by default once an attribute is named",
			query: "sortBy=userName",
			want:  SearchRequest{StartIndex: 1, Count: DefaultLimits.DefaultCount, SortBy: "userName", SortOrder: SortAscending},
		},
		{
			name:  "sorts descending when asked",
			query: "sortBy=name.givenName&sortOrder=descending",
			want:  SearchRequest{StartIndex: 1, Count: DefaultLimits.DefaultCount, SortBy: "name.givenName", SortOrder: SortDescending},
		},
		{
			name:  "leaves the order unsaid when no attribute is named",
			query: "sortOrder=descending",
			want:  SearchRequest{StartIndex: 1, Count: DefaultLimits.DefaultCount, SortOrder: SortDescending},
		},
		{
			name:  "carries the filter through for the server to interpret",
			query: "filter=" + url.QueryEscape(`userName eq "bjensen"`),
			want:  SearchRequest{StartIndex: 1, Count: DefaultLimits.DefaultCount, Filter: `userName eq "bjensen"`},
		},
		{
			name:  "reads the attribute lists as the comma separated values they are",
			query: "attributes=userName,active&excludedAttributes=meta,groups",
			want: SearchRequest{
				StartIndex:         1,
				Count:              DefaultLimits.DefaultCount,
				Attributes:         []string{"userName", "active"},
				ExcludedAttributes: []string{"meta", "groups"},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request, err := parseQuery(t, tc.query)

			require.NoError(t, err)

			tc.want.Schemas = []core.SchemaURI{SchemaSearchRequest}
			assert.Equal(t, &tc.want, request)
		})
	}

	for _, tc := range []struct {
		name, query, detail string
	}{
		{"a start index that is not a number", "startIndex=first", "startIndex"},
		{"a count that is not a number", "count=all", "count"},
		{"an order that is neither ascending nor descending", "sortBy=userName&sortOrder=sideways", "sortOrder"},
	} {
		t.Run("rejects "+tc.name, func(t *testing.T) {
			request, err := parseQuery(t, tc.query)

			require.Nil(t, request)
			require.ErrorIs(t, err, ErrInvalidValue(""))
			assert.Contains(t, err.Error(), tc.detail)
		})
	}
}

func TestSearchRequest(t *testing.T) {
	t.Run("converts the 1-based start index into a 0-based offset", func(t *testing.T) {
		assert.Equal(t, 0, (&SearchRequest{StartIndex: 1}).Offset())
		assert.Equal(t, 10, (&SearchRequest{StartIndex: 11}).Offset())
	})

	t.Run("reads a start index it was never given as the first", func(t *testing.T) {
		assert.Equal(t, 0, (&SearchRequest{}).Offset())
	})

	t.Run("reports the direction of the sort", func(t *testing.T) {
		assert.True(t, (&SearchRequest{SortOrder: SortDescending}).Descending())
		assert.False(t, (&SearchRequest{SortOrder: SortAscending}).Descending())
		assert.False(t, (&SearchRequest{}).Descending())
	})

	t.Run("serializes as the SearchRequest of RFC 7644, Section 3.4.3", func(t *testing.T) {
		request := &SearchRequest{
			Schemas:            []core.SchemaURI{SchemaSearchRequest},
			Attributes:         []string{"displayName", "userName"},
			ExcludedAttributes: []string{"meta"},
			Filter:             `displayName sw "smith"`,
			SortBy:             "displayName",
			SortOrder:          SortAscending,
			StartIndex:         1,
			Count:              10,
		}

		body, err := json.Marshal(request)

		require.NoError(t, err)
		require.JSONEq(t, `{
			"schemas": ["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],
			"attributes": ["displayName", "userName"],
			"excludedAttributes": ["meta"],
			"filter": "displayName sw \"smith\"",
			"sortBy": "displayName",
			"sortOrder": "ascending",
			"startIndex": 1,
			"count": 10
		}`, string(body))
	})

	t.Run("decodes the body a client posts to .search", func(t *testing.T) {
		var request SearchRequest
		require.NoError(t, json.Unmarshal([]byte(`{
			"schemas": ["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],
			"filter": "userName eq \"bjensen\"",
			"startIndex": 11,
			"count": 10
		}`), &request))

		assert.Equal(t, `userName eq "bjensen"`, request.Filter)
		assert.Equal(t, 10, request.Offset())
	})
}
