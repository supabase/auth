package utilities

import (
	"net/url"
	"strings"
)

// PreserveEmptyAuthority restores the `//` in URLs that use "scheme://" with
// an empty authority (e.g. custom-scheme deep links like "myapp://"). Go's
// net/url package normalizes these to "scheme:" on String(), which breaks
// iOS/Android deep-link clients that register for the "scheme://" form.
//
// u.Scheme is lowercased by url.Parse, so the prefix check against rurl is
// case-insensitive. When u has a userinfo, String() already writes the `//`.
func PreserveEmptyAuthority(rurl string, u *url.URL) string {
	formatted := u.String()
	if u.Scheme == "" || u.Host != "" || u.Path != "" || u.User != nil {
		return formatted
	}
	prefix := u.Scheme + "://"
	if len(rurl) < len(prefix) || !strings.EqualFold(rurl[:len(prefix)], prefix) {
		return formatted
	}
	return prefix + strings.TrimPrefix(formatted, u.Scheme+":")
}
