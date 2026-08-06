package utilities

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPreserveEmptyAuthority(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"custom scheme empty authority", "myapp://", "myapp://?code=ABC"},
		{"custom scheme with host", "myapp://host", "myapp://host?code=ABC"},
		{"scheme only no slashes", "myapp:", "myapp:?code=ABC"},
		{"https", "https://example.com", "https://example.com?code=ABC"},
		{"reverse dns empty authority", "com.example.app://", "com.example.app://?code=ABC"},
		{"reverse dns with path", "com.example.app://callback", "com.example.app://callback?code=ABC"},
		{"triple slash", "myapp:///callback", "myapp:///callback?code=ABC"},
		{"host port path", "myapp://host:1234/callback", "myapp://host:1234/callback?code=ABC"},
		{"existing query", "myapp://?x=1", "myapp://?code=ABC&x=1"},
		{"existing code param overwrites", "myapp://?code=OLD", "myapp://?code=ABC"},
		{"fragment", "myapp://#frag", "myapp://?code=ABC#frag"},
		// net/url lowercases the scheme per RFC 3986 §3.1. iOS URL-scheme
		// matching is case-sensitive in practice, so mixed-case schemes are
		// normalized to lowercase by the time they reach the client.
		{"mixed case scheme", "MyApp://callback", "myapp://callback?code=ABC"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u, err := url.Parse(c.in)
			require.NoError(t, err)
			q := u.Query()
			q.Set("code", "ABC")
			u.RawQuery = q.Encode()
			got := PreserveEmptyAuthority(c.in, u)
			assert.Equal(t, c.want, got)
		})
	}
}
