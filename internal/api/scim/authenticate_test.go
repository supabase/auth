package scim

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseBearerToken(t *testing.T) {
	// RFC 7235, Section 2.1: credentials = auth-scheme 1*SP token68.
	// The scheme is case insensitive and one or more spaces may separate it
	// from the token.
	accepted := map[string]string{
		"Bearer tok":   "tok",
		"bearer tok":   "tok",
		"BEARER tok":   "tok",
		"Bearer  tok":  "tok",
		"Bearer tok ":  "tok",
		"Bearer \ttok": "tok",
	}

	for header, want := range accepted {
		t.Run(header, func(t *testing.T) {
			got, ok := parseBearerToken(header)

			require.True(t, ok)
			require.Equal(t, want, got)
		})
	}

	rejected := []string{
		"",
		"Bearer",
		"Bearer ",
		"Basic tok",
		"Bearertok",
		"Bearer tok extra",
	}

	for _, header := range rejected {
		t.Run("rejects "+header, func(t *testing.T) {
			got, ok := parseBearerToken(header)

			require.False(t, ok)
			require.Empty(t, got)
		})
	}
}
