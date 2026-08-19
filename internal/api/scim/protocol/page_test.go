package protocol

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePage(t *testing.T) {
	for _, tc := range []struct {
		name       string
		query      string
		startIndex int
		count      int
	}{
		{
			name:       "defaults to the whole first page when the client asks for nothing",
			query:      "",
			startIndex: 1,
			count:      DefaultCount,
		},
		{
			name:       "honours the window the client asked for",
			query:      "startIndex=11&count=10",
			startIndex: 11,
			count:      10,
		},
		{
			name:       "caps a count larger than the provider is willing to return",
			query:      "count=5000",
			startIndex: 1,
			count:      MaxCount,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values, err := url.ParseQuery(tc.query)
			require.NoError(t, err)

			page, err := ParsePage(values)

			require.NoError(t, err)
			assert.Equal(t, tc.startIndex, page.StartIndex)
			assert.Equal(t, tc.count, page.Count)
		})
	}
}

func TestPageOffset(t *testing.T) {
	t.Run("converts the 1-based start index into a 0-based offset", func(t *testing.T) {
		require.Equal(t, 0, Page{StartIndex: 1}.Offset())
		require.Equal(t, 10, Page{StartIndex: 11}.Offset())
	})
}
