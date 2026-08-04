package protocol

import (
	"net/http"
	"strconv"
)

const SchemaError = "urn:ietf:params:scim:api:messages:2.0:Error"

// Error keywords defined in RFC 7644, Section 3.12
const (
	ErrorInvalidFilter = "invalidFilter"
	ErrorTooMany       = "tooMany"
	ErrorUniqueness    = "uniqueness"
	ErrorMutability    = "mutability"
	ErrorInvalidSyntax = "invalidSyntax"
	ErrorInvalidPath   = "invalidPath"
	ErrorNoTarget      = "noTarget"
	ErrorInvalidValue  = "invalidValue"
	ErrorInvalidVers   = "invalidVers"
	ErrorSensitive     = "sensitive"
)

// Error is the error message form defined in RFC 7644, Section 3.12.
type Error struct {
	Schemas  []string `json:"schemas"`
	ScimType string   `json:"scimType,omitempty"`
	Detail   string   `json:"detail,omitempty"`
	Status   string   `json:"status"`
}

func NewError(status int, scimType string, detail string) *Error {
	return &Error{
		Schemas:  []string{SchemaError},
		Status:   strconv.Itoa(status),
		ScimType: scimType,
		Detail:   detail,
	}
}

func (e *Error) StatusCode() int {
	status, err := strconv.Atoi(e.Status)
	if err != nil {
		return http.StatusInternalServerError
	}
	return status
}

func (e *Error) Error() string {
	detail := e.Detail
	if detail == "" {
		detail = http.StatusText(e.StatusCode())
	}
	return e.Status + ": " + detail
}
