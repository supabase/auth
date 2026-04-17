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
		{"fragment", "myapp://#frag", "myapp://?code=ABC#frag"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u, err := url.Parse(c.in)
			require.NoError(t, err)
			q := u.Query()
			q.Set("code", "ABC")
			u.RawQuery = q.Encode()
			got := PreserveEmptyAuthority(c.in, u, u.String())
			assert.Equal(t, c.want, got)
		})
	}
}
