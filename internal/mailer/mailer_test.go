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
		Params   map[string]string
		Expected string
	}{
		{
			SiteURL:  "https://test.example.com",
			Path:     "/templates/confirm.html",
			Params:   nil,
			Expected: "https://test.example.com/templates/confirm.html",
		},
		{
			SiteURL:  "https://test.example.com/removedpath",
			Path:     "/templates/confirm.html",
			Params:   nil,
			Expected: "https://test.example.com/templates/confirm.html",
		},
		{
			SiteURL:  "https://test.example.com/",
			Path:     "/trailingslash/",
			Params:   nil,
			Expected: "https://test.example.com/trailingslash/",
		},
		{
			SiteURL: "https://test.example.com",
			Path:    "f",
			Params: map[string]string{
				"key": "val",
			},
			Expected: "https://test.example.com/f?key=val",
		},
		{
			SiteURL: "https://test.example.com",
			Path:    "",
			Params: map[string]string{
				"key": "val",
			},
			Expected: "https://test.example.com?key=val",
		},
	}

	for _, c := range cases {
		u, err := url.ParseRequestURI(c.SiteURL)
		assert.NoError(t, err, "error parsing URI request")

		path, err := getPath(c.Path, c.Params)

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
