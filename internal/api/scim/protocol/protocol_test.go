package protocol

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSend(t *testing.T) {
	t.Run("writes an error with the SCIM media type", func(t *testing.T) {
		w := httptest.NewRecorder()

		require.NoError(t, Send(w, http.StatusNotFound, map[string]string{"key": "value"}))

		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Equal(t, "application/scim+json", w.Header().Get("Content-Type"))
		assert.JSONEq(t, `{"key":"value"}`, w.Body.String())
	})
}
