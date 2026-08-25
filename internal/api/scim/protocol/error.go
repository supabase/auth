package protocol

import (
	"net/http"
	"strconv"

	"github.com/supabase/auth/internal/api/scim/core"
)

// ErrorType is a detail error keyword from RFC 7644, Table 9.
type ErrorType string

const (
	ScimTypeInvalidFilter ErrorType = "invalidFilter"
	ScimTypeInvalidPath   ErrorType = "invalidPath"
	ScimTypeInvalidSyntax ErrorType = "invalidSyntax"
	ScimTypeInvalidValue  ErrorType = "invalidValue"
	ScimTypeInvalidVers   ErrorType = "invalidVers"
	ScimTypeMutability    ErrorType = "mutability"
	ScimTypeNoTarget      ErrorType = "noTarget"
	ScimTypeSensitive     ErrorType = "sensitive"
	ScimTypeTooMany       ErrorType = "tooMany"
	ScimTypeUniqueness    ErrorType = "uniqueness"
)

// Error is the error message form defined in RFC 7644, Section 3.12.
type Error struct {
	Schemas  []core.SchemaURI `json:"schemas"`
	ScimType ErrorType        `json:"scimType,omitempty"`
	Detail   string           `json:"detail,omitempty"`
	Status   string           `json:"status"`
}

func NewError(status int, scimType ErrorType, detail string) *Error {
	return &Error{
		Schemas:  []core.SchemaURI{SchemaError},
		ScimType: scimType,
		Detail:   detail,
		Status:   strconv.Itoa(status),
	}
}

func (e *Error) Error() string {
	message := "scim: " + e.Status
	if e.ScimType != "" {
		message += " " + string(e.ScimType)
	}
	if e.Detail != "" {
		message += ": " + e.Detail
	}
	return message
}

// StatusCode is the HTTP status the Error was built from, or 500 if unparsable.
func (e *Error) StatusCode() int {
	status, err := strconv.Atoi(e.Status)
	if err != nil {
		return http.StatusInternalServerError
	}
	return status
}

// Is reports whether target is an Error of the same status and scimType.
func (e *Error) Is(target error) bool {
	other, ok := target.(*Error)
	return ok && other.Status == e.Status && other.ScimType == e.ScimType
}

// The errors of RFC 7644, each pairing a scimType with the status the RFC states for it.

// ErrInvalidFilter reports a filter this provider cannot honour, per Table 3
// of Section 3.4.2.2.
func ErrInvalidFilter(detail string) *Error {
	return NewError(http.StatusBadRequest, ScimTypeInvalidFilter, detail)
}

// ErrTooMany reports a query whose result set is larger than this provider is
// willing to process, per Section 3.4.2.
func ErrTooMany(detail string) *Error {
	return NewError(http.StatusBadRequest, ScimTypeTooMany, detail)
}

// ErrInvalidSyntax reports a request body that does not conform to the request
// schema, per Section 3.12.
func ErrInvalidSyntax(detail string) *Error {
	return NewError(http.StatusBadRequest, ScimTypeInvalidSyntax, detail)
}

// ErrInvalidPath reports a malformed PATCH path, per Section 3.5.2.
func ErrInvalidPath(detail string) *Error {
	return NewError(http.StatusBadRequest, ScimTypeInvalidPath, detail)
}

// ErrNoTarget reports a PATCH path that yielded nothing to operate on, per
// Section 3.5.2.
func ErrNoTarget(detail string) *Error {
	return NewError(http.StatusBadRequest, ScimTypeNoTarget, detail)
}

// ErrInvalidValue reports a required value that is missing or unacceptable,
// per Table 8 of Section 3.12.
func ErrInvalidValue(detail string) *Error {
	return NewError(http.StatusBadRequest, ScimTypeInvalidValue, detail)
}

// ErrMutability reports a modification the target attribute does not allow,
// per Section 3.5.2.
func ErrMutability(detail string) *Error {
	return NewError(http.StatusBadRequest, ScimTypeMutability, detail)
}

// ErrUniqueness reports a value already in use, per Section 3.3.
func ErrUniqueness(detail string) *Error {
	return NewError(http.StatusConflict, ScimTypeUniqueness, detail)
}

// ErrSensitive reports a request that would disclose sensitive information in
// a URI, per Section 7.5.2.
func ErrSensitive(detail string) *Error {
	return NewError(http.StatusForbidden, ScimTypeSensitive, detail)
}

// The errors of Table 8, Section 3.12 that carry no scimType.

func ErrNotFound(detail string) *Error {
	return NewError(http.StatusNotFound, "", detail)
}

// ErrUnauthorized is the 401 of Section 3.12: the authorization header is
// missing or does not name a caller. A responder should also send
// WWW-Authenticate, per RFC 6750, Section 3.
func ErrUnauthorized(detail string) *Error {
	return NewError(http.StatusUnauthorized, "", detail)
}

func ErrForbidden(detail string) *Error {
	return NewError(http.StatusForbidden, "", detail)
}

// ErrTooLarge reports a request body larger than this provider will accept,
// the 413 of Table 9, Section 3.12.
func ErrTooLarge(detail string) *Error {
	return NewError(http.StatusRequestEntityTooLarge, "", detail)
}

func ErrNotImplemented(detail string) *Error {
	return NewError(http.StatusNotImplemented, "", detail)
}

func ErrInternal(detail string) *Error {
	return NewError(http.StatusInternalServerError, "", detail)
}
