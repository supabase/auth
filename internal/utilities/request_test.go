package utilities

import (
	"net/http"
	"net/http/httptest"
	tst "testing"

	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
)

func TestGetIPAddress(t *tst.T) {
	examples := []func(r *http.Request) string{
		func(r *http.Request) string {
			r.Header = nil
			r.RemoteAddr = "127.0.0.1:8080"

			return "127.0.0.1"
		},

		func(r *http.Request) string {
			r.Header = nil
			r.RemoteAddr = "incorrect"

			return "incorrect"
		},

		func(r *http.Request) string {
			r.Header = make(http.Header)
			r.RemoteAddr = "127.0.0.1:8080"

			return "127.0.0.1"
		},

		func(r *http.Request) string {
			r.Header = make(http.Header)
			r.RemoteAddr = "[::1]:8080"

			return "::1"
		},

		func(r *http.Request) string {
			r.Header = make(http.Header)
			r.RemoteAddr = "127.0.0.1:8080"
			r.Header.Add("X-Forwarded-For", "127.0.0.2")

			return "127.0.0.2"
		},

		func(r *http.Request) string {
			r.Header = make(http.Header)
			r.RemoteAddr = "127.0.0.1:8080"
			r.Header.Add("X-Forwarded-For", "127.0.0.2")

			return "127.0.0.2"
		},

		func(r *http.Request) string {
			r.Header = make(http.Header)
			r.RemoteAddr = "127.0.0.1:8080"
			r.Header.Add("X-Forwarded-For", "127.0.0.2,")

			return "127.0.0.2"
		},

		func(r *http.Request) string {
			r.Header = make(http.Header)
			r.RemoteAddr = "127.0.0.1:8080"
			r.Header.Add("X-Forwarded-For", "127.0.0.2,127.0.0.3")

			return "127.0.0.2"
		},

		func(r *http.Request) string {
			r.Header = make(http.Header)
			r.RemoteAddr = "127.0.0.1:8080"
			r.Header.Add("X-Forwarded-For", "::1,127.0.0.2")

			return "::1"
		},
	}

	for _, example := range examples {
		req := &http.Request{}
		expected := example(req)

		require.Equal(t, GetIPAddress(req), expected)
	}
}

func TestGetReferrer(t *tst.T) {
	config := conf.GlobalConfiguration{
		SiteURL:      "https://example.com",
		URIAllowList: []string{"http://localhost:8000/*"},
		JWT: conf.JWTConfiguration{
			Secret: "testsecret",
		},
	}
	require.NoError(t, config.ApplyDefaults())
	cases := []struct {
		desc        string
		redirectURL string
		expected    string
	}{
		{
			desc:        "valid redirect url",
			redirectURL: "http://localhost:8000/path",
			expected:    "http://localhost:8000/path",
		},
		{
			desc:        "invalid redirect url",
			redirectURL: "http://localhost:3000",
			expected:    config.SiteURL,
		},
		{
			desc:        "no / separator",
			redirectURL: "http://localhost:8000",
			expected:    config.SiteURL,
		},
		{
			desc:        "* respects separator",
			redirectURL: "http://localhost:8000/path/to/page",
			expected:    config.SiteURL,
		},
	}

	for _, c := range cases {
		t.Run(c.desc, func(t *tst.T) {
			r := httptest.NewRequest("GET", "http://localhost?redirect_to="+c.redirectURL, nil)
			referrer := GetReferrer(r, &config)
			require.Equal(t, c.expected, referrer)
		})
	}
}
