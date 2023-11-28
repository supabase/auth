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

type MFAVerificationAttemptInput struct {
	UserID   uuid.UUID `json:"user_id"`
	FactorID uuid.UUID `json:"factor_id"`
	Valid    bool      `json:"valid"`
}

type MFAVerificationAttemptOutput struct {
	Decision string `json:"decision"`
	Message  string `json:"message"`
}

type AuthHookError struct {
	Code    string `json:"code"`
	Message string `json:"msg"`
	ErrorID string `json:"error_id,omitempty"`
}

func (a *AuthHookError) Error() string {
	return fmt.Sprintf("%s: %s", a.Code, a.Message)
}

// Hook Events
const (
	MFAVerificationAttempt = "auth.mfa_verfication"
)

const (
	DefaultMFAHookRejectionMessage = "mfa attempt rejected"
)

type AuthHookErrorResponse struct {
	AuthHookError
}

func HookError(message string, args ...interface{}) *AuthHookError {
	return &AuthHookError{
		Message: fmt.Sprintf(message, args...),
	}

}

func (hookError *AuthHookErrorResponse) IsError() bool {
	return hookError.Message != ""
}
