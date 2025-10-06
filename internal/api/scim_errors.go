package api

import (
	"encoding/json"
	"net/http"
)

// SCIMError represents a SCIM error response according to RFC 7644 Section 3.12
type SCIMError struct {
	Schemas  []string       `json:"schemas"`
	Status   string         `json:"status"`
	ScimType string         `json:"scimType,omitempty"`
	Detail   string         `json:"detail,omitempty"`
	Meta     *SCIMErrorMeta `json:"meta,omitempty"`
}

type SCIMErrorMeta struct {
	ResourceType string `json:"resourceType,omitempty"`
}

const scimErrorSchema = "urn:ietf:params:scim:api:messages:2.0:Error"

// Common SCIM error types
const (
	SCIMErrorTypeInvalidFilter = "invalidFilter"
	SCIMErrorTypeInvalidPath   = "invalidPath"
	SCIMErrorTypeInvalidValue  = "invalidValue"
	SCIMErrorTypeTooMany       = "tooMany"
	SCIMErrorTypeUniqueness    = "uniqueness"
	SCIMErrorTypeMutability    = "mutability"
	SCIMErrorTypeInvalidSyntax = "invalidSyntax"
	SCIMErrorTypeNoTarget      = "noTarget"
	SCIMErrorTypeSensitive     = "sensitive"
)

// NewSCIMError creates a new SCIM error
func NewSCIMError(status int, scimType, detail string) *SCIMError {
	return &SCIMError{
		Schemas:  []string{scimErrorSchema},
		Status:   http.StatusText(status),
		ScimType: scimType,
		Detail:   detail,
	}
}

// SCIMBadRequest returns a 400 Bad Request SCIM error
func SCIMBadRequest(scimType, detail string) error {
	return &scimError{
		statusCode: http.StatusBadRequest,
		err:        NewSCIMError(http.StatusBadRequest, scimType, detail),
	}
}

// SCIMUnauthorized returns a 401 Unauthorized SCIM error
func SCIMUnauthorized(detail string) error {
	return &scimError{
		statusCode: http.StatusUnauthorized,
		err:        NewSCIMError(http.StatusUnauthorized, "", detail),
	}
}

// SCIMForbidden returns a 403 Forbidden SCIM error
func SCIMForbidden(detail string) error {
	return &scimError{
		statusCode: http.StatusForbidden,
		err:        NewSCIMError(http.StatusForbidden, "", detail),
	}
}

// SCIMNotFound returns a 404 Not Found SCIM error
func SCIMNotFound(detail string) error {
	return &scimError{
		statusCode: http.StatusNotFound,
		err:        NewSCIMError(http.StatusNotFound, "", detail),
	}
}

// SCIMConflict returns a 409 Conflict SCIM error
func SCIMConflict(scimType, detail string) error {
	return &scimError{
		statusCode: http.StatusConflict,
		err:        NewSCIMError(http.StatusConflict, scimType, detail),
	}
}

// SCIMInternalError returns a 500 Internal Server Error SCIM error
func SCIMInternalError(detail string) error {
	return &scimError{
		statusCode: http.StatusInternalServerError,
		err:        NewSCIMError(http.StatusInternalServerError, "", detail),
	}
}

// scimError implements the error interface and holds both status code and SCIM error details
type scimError struct {
	statusCode int
	err        *SCIMError
}

func (e *scimError) Error() string {
	return e.err.Detail
}

func (e *scimError) StatusCode() int {
	return e.statusCode
}

func (e *scimError) SCIMError() *SCIMError {
	return e.err
}

// WriteSCIMError writes a SCIM error response
func WriteSCIMError(w http.ResponseWriter, err error) {
	if scimErr, ok := err.(*scimError); ok {
		w.Header().Set("Content-Type", "application/scim+json")
		w.WriteHeader(scimErr.StatusCode())
		_ = json.NewEncoder(w).Encode(scimErr.SCIMError())
		return
	}

	// Fallback for non-SCIM errors
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(http.StatusInternalServerError)
	_ = json.NewEncoder(w).Encode(NewSCIMError(http.StatusInternalServerError, "", "Internal server error"))
}

// IsSCIMError checks if an error is a SCIM error
func IsSCIMError(err error) bool {
	_, ok := err.(*scimError)
	return ok
}
