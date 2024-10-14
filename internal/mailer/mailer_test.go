package mailer

import (
	"net/url"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
)

var urlRegexp = regexp.MustCompile(`^https?://[^/]+`)

func enforceRelativeURL(url string) string {
	return urlRegexp.ReplaceAllString(url, "")
}

func TestGetPath(t *testing.T) {
	params := EmailParams{
		Token:      "token",
		Type:       "signup",
		RedirectTo: "https://example.com",
	}
	cases := []struct {
		SiteURL  string
		Path     string
		Params   *EmailParams
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
			SiteURL:  "https://test.example.com",
			Path:     "f",
			Params:   &params,
			Expected: "https://test.example.com/f?token=token&type=signup&redirect_to=https://example.com",
		},
		{
			SiteURL:  "https://test.example.com",
			Path:     "",
			Params:   &params,
			Expected: "https://test.example.com?token=token&type=signup&redirect_to=https://example.com",
		},
	}

	for _, c := range cases {
		u, err := url.ParseRequestURI(c.SiteURL)
		assert.NoError(t, err, "error parsing URI request")

		path, err := getPath(c.Path, c.Params)

		assert.NoError(t, err)
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

func TestGetProjectRefFromHeaders(t *testing.T) {
	cases := []struct {
		from string
		exp  string
		ok   bool
	}{
		{
			from: `{"x-supabase-project-ref": ["abcjrhohrqmvcpjpsyzc"]}`,
			exp:  "abcjrhohrqmvcpjpsyzc",
			ok:   true,
		},
		{
			from: `{"X-Supabase-Project-Ref": ["abcjrhohrqmvcpjpsyzc"]}`,
			exp:  "abcjrhohrqmvcpjpsyzc",
			ok:   true,
		},
		{
			from: `{"X-Other-Headers": ["somevalue"]}`,
			exp:  "",
			ok:   false,
		},
		{
			from: `{"x-supabase-project-ref": [""]}`,
			exp:  "",
			ok:   false,
		},
		{
			from: ``,
			exp:  "",
			ok:   false,
		},
		{
			from: `{"x-supabase-project-ref": null}`,
			exp:  "",
			ok:   false,
		},
	}
	for _, tc := range cases {
		mailer := TemplateMailer{
			Config: &conf.GlobalConfiguration{
				SMTP: conf.SMTPConfiguration{
					Headers: tc.from,
				},
			},
		}
		require.NoError(t, mailer.Config.SMTP.Validate())

		hdrs := mailer.Headers(tc.from)
		ref, ok := getProjectRefFromHeaders(hdrs)
		if exp, got := tc.ok, ok; exp != got {
			t.Fatalf("exp %v; got %v", exp, got)
		}
		if exp, got := tc.exp, ref; exp != got {
			t.Fatalf("exp %v; got %v", exp, got)
		}
	}
}
