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
		// net/url lowercases the scheme (RFC 3986 §3.1 says schemes are
		// case-insensitive), so the output scheme is always lowercase.
		{"mixed case scheme", "MyApp://callback", "myapp://callback?code=ABC"},
		{"mixed case scheme empty authority", "MyApp://", "myapp://?code=ABC"},
		{"upper case scheme empty authority", "MYAPP://", "myapp://?code=ABC"},
		{"mixed case reverse dns empty authority", "Com.Example.App://", "com.example.app://?code=ABC"},
		{"userinfo empty host", "myapp://user@", "myapp://user@?code=ABC"},
		{"empty userinfo empty host", "myapp://@", "myapp://@?code=ABC"},
		{"userinfo with password empty host", "myapp://user:pass@", "myapp://user:pass@?code=ABC"},
		{"userinfo with host", "myapp://user@host", "myapp://user@host?code=ABC"},
		{"empty host with port", "myapp://:8080", "myapp://:8080?code=ABC"},
		{"single slash path", "myapp:/callback", "myapp:/callback?code=ABC"},
		{"opaque", "myapp:callback", "myapp:callback?code=ABC"},
		{"scheme with plus dot dash", "my-app+x.y://", "my-app+x.y://?code=ABC"},
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
