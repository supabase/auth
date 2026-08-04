package shared

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSendJSONAs(t *testing.T) {
	t.Run("with an empty body", func(t *testing.T) {
		w := httptest.NewRecorder()

		require.NoError(t, SendJSONAs(w, http.StatusTeapot, "application/example+json", nil))

		assert.Equal(t, http.StatusTeapot, w.Code)
		assert.Equal(t, "application/example+json", w.Header().Get("Content-Type"))
		assert.Equal(t, "", w.Body.String())
	})

	t.Run("with a JSON body", func(t *testing.T) {
		w := httptest.NewRecorder()

		require.NoError(t, SendJSONAs(w, http.StatusTeapot, "application/example+json", map[string]string{"key": "value"}))

		assert.Equal(t, http.StatusTeapot, w.Code)
		assert.Equal(t, "application/example+json", w.Header().Get("Content-Type"))
		assert.Equal(t, `{"key":"value"}`, w.Body.String())
	})
}
