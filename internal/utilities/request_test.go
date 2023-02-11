package utilities

import (
	"net/http"
	tst "testing"

	"github.com/stretchr/testify/require"
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
