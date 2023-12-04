package hooks

import (
	"github.com/gofrs/uuid"
)

type HookType string

const (
	PostgresHook HookType = "pg-functions"
)

const AccessTokenSchema = `{
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "properties": {
        "Subject": {"type": "string"},
        "Audience": {"type": "array", "items": {"type": "string"}},
        "IssuedAt": {"type": "integer"},
        "ExpiresAt": {"type": "integer"},
        "Issuer": {"type": "string"},
        "Email": {"type": "string", "format": "email"},
        "Phone": {"type": "string"}, // Assuming phone is in string format
        "AppMetaData": {"type": "object"}, // Assuming AppMetaData is a JSON object
        "UserMetaData": {"type": "object"}, // Assuming UserMetaData is a JSON object
        "Role": {"type": "string"},
        "SessionId": {"type": "string"},
        "AuthenticatorAssuranceLevel": {"type": "integer"},
        "AuthenticationMethodReference": {"type": "array", "items": {"type": "string"}}
    },
    "required": [
        "Subject",
        "Audience",
        "IssuedAt",
        "ExpiresAt",
        "Issuer",
        "Email",
        "Phone",
        "AppMetaData",
        "UserMetaData",
        "Role",
        "SessionId",
        "AuthenticatorAssuranceLevel",
        "AuthenticationMethodReference"
    ],
    "additionalProperties": true
}`

const (
	// In Miliseconds
	DefaultTimeout = 2000
)

// Hook Names
const (
	HookRejection = "reject"
)

type HookOutput interface {
	IsError() bool
	Error() string
}

type MFAVerificationAttemptInput struct {
	UserID   uuid.UUID `json:"user_id"`
	FactorID uuid.UUID `json:"factor_id"`
	Valid    bool      `json:"valid"`
}

type MFAVerificationAttemptOutput struct {
	Decision  string        `json:"decision"`
	Message   string        `json:"message"`
	HookError AuthHookError `json:"error"`
}

type PasswordVerificationAttemptInput struct {
	UserID uuid.UUID `json:"user_id"`
	Valid  bool      `json:"valid"`
}

type PasswordVerificationAttemptOutput struct {
	Decision         string        `json:"decision"`
	Message          string        `json:"message"`
	ShouldLogoutUser bool          `json:"should_logout_user"`
	HookError        AuthHookError `json:"error"`
}

type CustomAccessTokenInput struct {
	UserID      uuid.UUID `json:"user_id"`
	AccessToken string    `json:"access_token"`
}

type CustomAccessTokenOutput struct {
	HookError AuthHookError `json:"error,omitempty"`
}

func (mf *MFAVerificationAttemptOutput) IsError() bool {
	return mf.HookError.Message != ""
}

func (mf *MFAVerificationAttemptOutput) Error() string {
	return mf.HookError.Message
}

func (p *PasswordVerificationAttemptOutput) IsError() bool {
	return p.HookError.Message != ""
}

func (p *PasswordVerificationAttemptOutput) Error() string {
	return p.HookError.Message
}

func (ca *CustomAccessTokenOutput) IsError() bool {
	return ca.HookError.Message != ""
}

func (ca *CustomAccessTokenOutput) Error() string {
	return ca.HookError.Message
}

type AuthHookError struct {
	HTTPCode int    `json:"http_code,omitempty"`
	Message  string `json:"message,omitempty"`
}

func (a *AuthHookError) Error() string {
	return a.Message
}

const (
	DefaultMFAHookRejectionMessage      = "Further MFA verification attempts will be rejected."
	DefaultPasswordHookRejectionMessage = "Further password verification attempts will be rejected."
)
