package scim

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCredential(t *testing.T) {
	for _, tc := range []struct{ name, header, expected string }{
		{"a bearer token", "Bearer scim_abc", "scim_abc"},
		{"a lowercase scheme, per RFC 7235", "bearer scim_abc", "scim_abc"},
		{"a mixed case scheme", "BeArEr scim_abc", "scim_abc"},
		{"surrounding whitespace", "Bearer   scim_abc  ", "scim_abc"},
		{"no header at all", "", ""},
		{"another scheme", "Basic dXNlcjpwYXNzd29yZA==", ""},
		{"the scheme with nothing after it", "Bearer ", ""},
		{"the scheme alone", "Bearer", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, BasePath+"/Users", nil)
			if tc.header != "" {
				r.Header.Set("Authorization", tc.header)
			}

			assert.Equal(t, tc.expected, credential(r))
		})
	}
}
