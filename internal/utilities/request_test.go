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
		URIAllowList: []string{"http://localhost:8000/*", "http://*.localhost:8000/*", "http://*:12345/*", "http://**:12345/*"},
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
		{
			desc:        "* respects parameters",
			redirectURL: "http://localhost:8000/path?param=1",
			expected:    "http://localhost:8000/path?param=1",
		},
		{
			desc:        "invalid redirect url due to decimal IP address",
			redirectURL: "http://123?.localhost:8000/path",
			expected:    config.SiteURL,
		},
		{
			desc:        "invalid redirect url due to IPv4 address",
			redirectURL: "http://123.123.123.123?localhost:8000/path",
			expected:    config.SiteURL,
		},
		{
			desc:        "invalid redirect url due to IPv6 address",
			redirectURL: "http://[65e7:9410:d8b6:e227:58cd:e55b:8fc0:206d]?localhost:8000/path",
			expected:    config.SiteURL,
		},
		{
			desc:        "invalid redirect url due to bad URL",
			redirectURL: "http://65e7:9410:d8b6:e227:58cd:e55b:8fc0:206d?localhost:8000/path",
			expected:    config.SiteURL,
		},
		{
			desc:        "valid loopback IPv4 address",
			redirectURL: "http://127.0.0.1:12345/path",
			expected:    "http://127.0.0.1:12345/path",
		},
		{
			desc:        "valid loopback IPv6 address",
			redirectURL: "http://[0:0:0:0:0:0:0:1]:12345/path",
			expected:    "http://[0:0:0:0:0:0:0:1]:12345/path",
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
