package protocol

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api/scim/fixtures"
)

func TestNewError(t *testing.T) {
	t.Run("serializes to JSON correctly", func(t *testing.T) {
		body, err := json.Marshal(NewError(http.StatusBadRequest, ErrorInvalidFilter, "The specified filter syntax was invalid"))

		require.NoError(t, err)
		assert.JSONEq(t, fixtures.InvalidFilter, string(body))
	})

	t.Run("omits the optional attributes when they are empty", func(t *testing.T) {
		body, err := json.Marshal(NewError(http.StatusMethodNotAllowed, "", ""))

		require.NoError(t, err)
		assert.JSONEq(t, fixtures.MethodNotAllowedWithoutDetail, string(body))
	})
}

func TestErrorStatusCode(t *testing.T) {
	t.Run("reads the status back from the wire form", func(t *testing.T) {
		require.Equal(t, http.StatusForbidden, NewError(http.StatusForbidden, "", "").StatusCode())
	})

	t.Run("survives a round trip through JSON", func(t *testing.T) {
		var scimErr Error
		require.NoError(t, json.Unmarshal([]byte(fixtures.NotFound), &scimErr))

		assert.Equal(t, http.StatusNotFound, scimErr.StatusCode())
		assert.Equal(t, "404", scimErr.Status)
		assert.Equal(t, "Endpoint or resource does not exist", scimErr.Detail)
		assert.Equal(t, []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, scimErr.Schemas)
	})

	t.Run("falls back to a server error when the status is not a number", func(t *testing.T) {
		require.Equal(t, http.StatusInternalServerError, (&Error{Status: "nonsense"}).StatusCode())
	})
}

func TestErrorError(t *testing.T) {
	t.Run("reads as an error", func(t *testing.T) {
		var err error = NewError(http.StatusNotFound, "", "Endpoint or resource does not exist")

		assert.EqualError(t, err, "404: Endpoint or resource does not exist")
	})

	t.Run("falls back to the status text when there is no detail", func(t *testing.T) {
		var err error = NewError(http.StatusMethodNotAllowed, "", "")

		require.EqualError(t, err, "405: Method Not Allowed")
	})
}
