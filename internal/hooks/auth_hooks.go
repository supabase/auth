package hooks

import (
	"github.com/gofrs/uuid"
)

type HookType string

const (
	PostgresHook HookType = "pg-functions"
)

const (
	// In Miliseconds
	DefaultTimeout = 2000
)

// Hook Names
const (
	MFAHookRejection = "reject"
	MFAHookContinue  = "continue"
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
	Decision string `json:"decision,omitempty"`
	Message  string `json:"message,omitempty"`

	HookError AuthHookError `json:"error,omitempty"`
}

func (mf *MFAVerificationAttemptOutput) IsError() bool {
	return mf.HookError.Message != ""
}

func (mf *MFAVerificationAttemptOutput) Error() string {
	return mf.HookError.Message
}

type AuthHookError struct {
	HTTPCode int    `json:"http_code,omitempty"`
	Message  string `json:"message,omitempty"`
}

func (a *AuthHookError) Error() string {
	return a.Message
}

const (
	DefaultMFAHookRejectionMessage = "Further MFA verification attempts will be rejected."
)
