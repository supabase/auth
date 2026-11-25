package templatemailer

import (
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
)

var urlRegexp = regexp.MustCompile(`^https?://[^/]+`)

func enforceRelativeURL(url string) string {
	return urlRegexp.ReplaceAllString(url, "")
}

func TestGetPath(t *testing.T) {
	params := emailParams{
		Token:      "token",
		Type:       "signup",
		RedirectTo: "https://example.com",
	}
	cases := []struct {
		SiteURL  string
		Path     string
		Params   *emailParams
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
			Expected: "https://test.example.com/removedpath/templates/confirm.html",
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
		assert.Equal(t, c.Expected, resolveEmailURL(u, path))
	}
}

func TestGetEmailActionLinkKeepsExternalURLPath(t *testing.T) {
	cfg := &conf.GlobalConfiguration{}
	cfg.Mailer.URLPaths.Recovery = "/verify"
	cfg.Mailer.URLPaths.Confirmation = "/verify"
	cfg.Mailer.URLPaths.Invite = "/verify"
	cfg.Mailer.URLPaths.EmailChange = "/verify"
	m := &Mailer{cfg: cfg}
	user := &models.User{
		RecoveryToken:           "tok",
		ConfirmationToken:       "ctok",
		EmailChangeTokenNew:     "ntok",
		EmailChangeTokenCurrent: "otok",
	}

	external, err := url.Parse("http://127.0.0.1:54321/auth/v1")
	assert.NoError(t, err)
	link, err := m.GetEmailActionLink(user, "magiclink", "https://app.example/welcome", external)
	assert.NoError(t, err)
	assert.True(t, strings.HasPrefix(link, "http://127.0.0.1:54321/auth/v1/verify?"), link)
	assert.Contains(t, link, "token=tok")
	assert.Contains(t, link, "type=magiclink")

	origin, err := url.Parse("https://project.supabase.co")
	assert.NoError(t, err)
	link, err = m.GetEmailActionLink(user, "signup", "https://app.example/welcome", origin)
	assert.NoError(t, err)
	assert.True(t, strings.HasPrefix(link, "https://project.supabase.co/verify?"), link)

	absolute, err := url.Parse("https://gateway.example/auth/v1/")
	assert.NoError(t, err)
	link, err = m.GetEmailActionLink(user, "recovery", "https://app.example/welcome", absolute)
	assert.NoError(t, err)
	assert.True(t, strings.HasPrefix(link, "https://gateway.example/auth/v1/verify?"), link)
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
