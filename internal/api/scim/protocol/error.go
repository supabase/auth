package protocol

import (
	"strconv"
)

// ScimType is a detail error keyword from RFC 7644, Table 9.
type ScimType string

const (
	ScimTypeInvalidFilter ScimType = "invalidFilter"
	ScimTypeInvalidPath   ScimType = "invalidPath"
	ScimTypeInvalidSyntax ScimType = "invalidSyntax"
	ScimTypeInvalidValue  ScimType = "invalidValue"
	ScimTypeInvalidVers   ScimType = "invalidVers"
	ScimTypeMutability    ScimType = "mutability"
	ScimTypeNoTarget      ScimType = "noTarget"
	ScimTypeSensitive     ScimType = "sensitive"
	ScimTypeTooMany       ScimType = "tooMany"
	ScimTypeUniqueness    ScimType = "uniqueness"
)

// Error is the error message form defined in RFC 7644, Section 3.12.
type Error struct {
	Schemas  []string `json:"schemas"`
	ScimType ScimType `json:"scimType,omitempty"`
	Detail   string   `json:"detail,omitempty"`
	Status   string   `json:"status"`
}

func NewError(status int, scimType ScimType, detail string) *Error {
	return &Error{
		Schemas:  []string{SchemaError},
		ScimType: scimType,
		Detail:   detail,
		Status:   strconv.Itoa(status),
	}
}
