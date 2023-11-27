package hooks

import (
	"net/url"

	"fmt"
	"github.com/gofrs/uuid"
	"github.com/supabase/gotrue/internal/conf"
	"regexp"
	"strings"
	"time"
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

// AuthHookError is an error with a message and an HTTP status code.
type AuthHookError struct {
	Code    int    `json:"code"`
	Message string `json:"msg"`
	ErrorID string `json:"error_id,omitempty"`
}

// Hook Events
const (
	MFAVerificationAttempt = "auth.mfa_verfication"
)

type AuthHookErrorResponse struct {
	AuthHookError
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
