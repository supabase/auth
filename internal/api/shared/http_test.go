package shared

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSendJSON(t *testing.T) {
	t.Run("with an empty body", func(t *testing.T) {
		w := httptest.NewRecorder()

		require.NoError(t, SendJSON(w, http.StatusTeapot, nil))

		assert.Equal(t, http.StatusTeapot, w.Code)
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
		assert.Equal(t, "", w.Body.String())
	})

	t.Run("with a JSON body", func(t *testing.T) {
		w := httptest.NewRecorder()

		require.NoError(t, SendJSON(w, http.StatusTeapot, map[string]string{"key": "value"}))

		assert.Equal(t, http.StatusTeapot, w.Code)
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
		assert.Equal(t, `{"key":"value"}`, w.Body.String())
	})
}

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
			r := httptest.NewRequest(http.MethodGet, "/Users", nil)
			if tc.header != "" {
				r.Header.Set("Authorization", tc.header)
			}

			assert.Equal(t, tc.expected, Credential(r))
		})
	}
}
