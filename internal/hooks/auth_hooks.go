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
