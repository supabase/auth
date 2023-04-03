package mailer

import (
	"net/url"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

var urlRegexp = regexp.MustCompile(`^https?://[^/]+`)

func enforceRelativeURL(url string) string {
	return urlRegexp.ReplaceAllString(url, "")
}

func TestGetPath(t *testing.T) {
	cases := []struct {
		SiteURL  string
		Path     string
		Fragment string
		Expected string
	}{
		{
			SiteURL:  "https://test.example.com",
			Path:     "/templates/confirm.html",
			Fragment: "",
			Expected: "https://test.example.com/templates/confirm.html",
		},
		{
			SiteURL:  "https://test.example.com/removedpath",
			Path:     "/templates/confirm.html",
			Fragment: "",
			Expected: "https://test.example.com/templates/confirm.html",
		},
		{
			SiteURL:  "https://test.example.com/",
			Path:     "/trailingslash/",
			Fragment: "",
			Expected: "https://test.example.com/trailingslash/",
		},
		{
			SiteURL:  "https://test.example.com",
			Path:     "f",
			Fragment: "fragment",
			Expected: "https://test.example.com/f?fragment",
		},
		{
			SiteURL:  "https://test.example.com",
			Path:     "f",
			Fragment: "fragment",
			Expected: "https://test.example.com/f?fragment",
		},
		{
			SiteURL:  "https://test.example.com",
			Path:     "",
			Fragment: "fragment",
			Expected: "https://test.example.com?fragment",
		},
	}

	for _, c := range cases {
		u, err := url.ParseRequestURI(c.SiteURL)
		assert.NoError(t, err, "error parsing URI request")

		path, err := getPath(c.Path, c.Fragment)

		assert.NoError(t, err, c.Expected)
		assert.Equal(t, c.Expected, u.ResolveReference(path).String())
	}
}

func TestRelativeURL(t *testing.T) {
	cases := []struct {
		URL      string
		Expected string
	}{
		{"https://test.example.com", ""},
		{"http://test.example.com", ""},
		{"test.example.com", "test.example.com"},
		{"/some/path#fragment", "/some/path#fragment"},
	}

	for _, c := range cases {
		res := enforceRelativeURL(c.URL)
		assert.Equal(t, c.Expected, res, c.URL)
	}
}
