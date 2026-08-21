package protocol

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api/scim/core"
)

func TestNewError(t *testing.T) {
	t.Run("serializes to JSON correctly", func(t *testing.T) {
		body, err := json.Marshal(NewError(http.StatusNotFound, "", "Endpoint or resource does not exist"))

		require.NoError(t, err)
		assert.JSONEq(t, `{
			"schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
			"status": "404",
			"detail": "Endpoint or resource does not exist"
		}`, string(body))
	})

	t.Run("includes the scimType when one is given", func(t *testing.T) {
		body, err := json.Marshal(NewError(http.StatusBadRequest, "invalidValue", "A required value was missing"))

		require.NoError(t, err)
		assert.JSONEq(t, `{
			"schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
			"scimType": "invalidValue",
			"detail": "A required value was missing",
			"status": "400"
		}`, string(body))
	})

	t.Run("omits the optional attributes when they are empty", func(t *testing.T) {
		body, err := json.Marshal(NewError(http.StatusBadRequest, "", ""))

		require.NoError(t, err)
		assert.JSONEq(t, `{
			"schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
			"status": "400"
		}`, string(body))
	})
}

func TestErrorIsAnError(t *testing.T) {
	t.Run("reports the status and the detail", func(t *testing.T) {
		var err error = NewError(http.StatusNotFound, "", "Endpoint or resource does not exist")

		require.EqualError(t, err, "scim: 404: Endpoint or resource does not exist")
	})

	t.Run("names the scimType when it carries one", func(t *testing.T) {
		var err error = ErrUniqueness(`userName "bjensen" is already in use`)

		require.EqualError(t, err, `scim: 409 uniqueness: userName "bjensen" is already in use`)
	})

	t.Run("reports the status alone when there is no detail", func(t *testing.T) {
		require.EqualError(t, NewError(http.StatusBadRequest, "", ""), "scim: 400")
		require.EqualError(t, ErrInvalidFilter(""), "scim: 400 invalidFilter")
	})

	t.Run("restates the wire status as a status code", func(t *testing.T) {
		assert.Equal(t, http.StatusConflict, ErrUniqueness("").StatusCode())
		assert.Equal(t, http.StatusInternalServerError, (&Error{Status: "not a number"}).StatusCode())
	})
}

func TestErrorIs(t *testing.T) {
	t.Run("matches another error of the same status and scimType", func(t *testing.T) {
		require.ErrorIs(t, ErrUniqueness("userName is already in use"), ErrUniqueness(""))
	})

	t.Run("distinguishes a different scimType", func(t *testing.T) {
		require.NotErrorIs(t, ErrInvalidPath("bad path"), ErrNoTarget(""))
	})

	t.Run("distinguishes a different status", func(t *testing.T) {
		require.NotErrorIs(t, ErrNotFound("no such user"), ErrNotImplemented(""))
	})

	t.Run("is recoverable from a wrapped error", func(t *testing.T) {
		wrapped := fmt.Errorf("listing users: %w", ErrTooMany("too many results"))

		var scimErr *Error
		require.ErrorAs(t, wrapped, &scimErr)
		assert.Equal(t, ScimTypeTooMany, scimErr.ScimType)
		require.ErrorIs(t, wrapped, ErrTooMany(""))
	})
}

// The status paired with each scimType is the one RFC 7644 states for it. The
// RFC pairs them in prose, not in a table, so each pairing cites its source.
func TestErrorConstructors(t *testing.T) {
	for _, tc := range []struct {
		name     string
		err      *Error
		status   int
		scimType ScimType
		cite     string
	}{
		{"ErrInvalidFilter", ErrInvalidFilter(""), http.StatusBadRequest, ScimTypeInvalidFilter, "Section 3.4.2.2, Table 3"},
		{"ErrTooMany", ErrTooMany(""), http.StatusBadRequest, ScimTypeTooMany, "Section 3.4.2"},
		{"ErrInvalidSyntax", ErrInvalidSyntax(""), http.StatusBadRequest, ScimTypeInvalidSyntax, "Section 3.12"},
		{"ErrInvalidPath", ErrInvalidPath(""), http.StatusBadRequest, ScimTypeInvalidPath, "Section 3.5.2"},
		{"ErrNoTarget", ErrNoTarget(""), http.StatusBadRequest, ScimTypeNoTarget, "Section 3.5.2"},
		{"ErrInvalidValue", ErrInvalidValue(""), http.StatusBadRequest, ScimTypeInvalidValue, "Section 3.12, Table 8"},
		{"ErrMutability", ErrMutability(""), http.StatusBadRequest, ScimTypeMutability, "Section 3.5.2"},
		{"ErrUniqueness", ErrUniqueness(""), http.StatusConflict, ScimTypeUniqueness, "Section 3.3"},
		{"ErrSensitive", ErrSensitive(""), http.StatusForbidden, ScimTypeSensitive, "Section 7.5.2"},
		{"ErrNotFound", ErrNotFound(""), http.StatusNotFound, "", "Section 3.12, Table 8"},
		{"ErrForbidden", ErrForbidden(""), http.StatusForbidden, "", "Section 3.12, Table 8"},
		{"ErrNotImplemented", ErrNotImplemented(""), http.StatusNotImplemented, "", "Section 3.12, Table 8"},
		{"ErrInternal", ErrInternal(""), http.StatusInternalServerError, "", "Section 3.12, Table 8"},
	} {
		t.Run(tc.name+" pairs "+strconv.Itoa(tc.status)+" with "+string(tc.scimType), func(t *testing.T) {
			assert.Equal(t, tc.status, tc.err.StatusCode(), tc.cite)
			assert.Equal(t, strconv.Itoa(tc.status), tc.err.Status, tc.cite)
			assert.Equal(t, tc.scimType, tc.err.ScimType, tc.cite)
			assert.Equal(t, []core.SchemaURI{SchemaError}, tc.err.Schemas)
		})
	}

	t.Run("carries the detail it was given", func(t *testing.T) {
		assert.Equal(t, "Filtering is not supported on this endpoint", ErrInvalidFilter("Filtering is not supported on this endpoint").Detail)
	})
}
