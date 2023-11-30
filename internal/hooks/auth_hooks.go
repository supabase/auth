package hooks

import (
	"fmt"
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
	Decision  string        `json:"decision"`
	Message   string        `json:"message"`
	HookError AuthHookError `json:"hook_error" split_words:"true"`
}

type AuthHookError struct {
	Code    string `json:"code"`
	Message string `json:"msg"`
	ErrorID string `json:"error_id,omitempty"`
}

func (a *AuthHookError) Error() string {
	return fmt.Sprintf("%s: %s", a.Code, a.Message)
}

const (
	DefaultMFAHookRejectionMessage = "Further MFA verification attempts will be rejected."
)

func HookError(message string, args ...interface{}) *AuthHookError {
	return &AuthHookError{
		Message: fmt.Sprintf(message, args...),
	}

}

func (mf *MFAVerificationAttemptOutput) IsError() bool {
	return mf.HookError.Message != ""
}
func (mf *MFAVerificationAttemptOutput) Error() string {
	return mf.HookError.Message
}
