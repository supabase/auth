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
// Call with the original input string, the parsed URL, and the already-
// serialized output of u.String().
func PreserveEmptyAuthority(rurl string, u *url.URL, formatted string) string {
	if u.Scheme != "" && u.Host == "" && u.Path == "" && strings.HasPrefix(rurl, u.Scheme+"://") {
		return strings.Replace(formatted, u.Scheme+":", u.Scheme+"://", 1)
	}
	return formatted
}
