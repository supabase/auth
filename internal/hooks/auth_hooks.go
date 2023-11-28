package hooks

import (
	"net/url"

	"fmt"
	"github.com/gofrs/uuid"
	"github.com/supabase/gotrue/internal/conf"
	"regexp"
	"strings"
)

type HookType string

const (
	PostgresHook HookType = "pg-functions"
	HTTPHook     HookType = "http"
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

func FetchHookName(ep conf.ExtensibilityPointConfiguration) (string, error) {
	// specification for Postgres names
	regExp := `^[a-zA-Z_][a-zA-Z0-9_]{0,62}$`
	re, err := regexp.Compile(regExp)
	if err != nil {
		return "", err
	}

	u, err := url.Parse(ep.URI)
	if err != nil {
		return "", err
	}
	pathParts := strings.Split(u.Path, "/")
	if len(pathParts) < 3 {
		return "", fmt.Errorf("URI path does not contain enough parts")
	}
	schema := pathParts[1]
	table := pathParts[2]
	// Validate schema and table names
	if !re.MatchString(schema) {
		return "", fmt.Errorf("invalid schema name: %s", schema)
	}
	if !re.MatchString(table) {
		return "", fmt.Errorf("invalid table name: %s", table)
	}

	return schema + "." + table, nil
}
