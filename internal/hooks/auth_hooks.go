package hooks

import (
	"encoding/json"
	"net/url"

	"fmt"
	"github.com/gofrs/uuid"
	"github.com/supabase/gotrue/internal/conf"
	"github.com/supabase/gotrue/internal/storage"
	"regexp"
	"strings"
)

type HookType string

const (
	PostgresHook HookType = "pg-functions"
	HTTPHook     HookType = "http"
)

const (
	MFAHookRejection = "reject"
	MFAHookContinue  = "continue"
)

type AuthHook struct {
	ExtensibilityPointConfiguration conf.ExtensibilityPointConfiguration
	Payload                         []byte
	HookType                        HookType
	Event                           string
	DB                              *storage.Connection
}

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

type HookErrorResponse struct {
	AuthHookError
}

func ParseErrorResponse(response []byte) (*HookErrorResponse, error) {
	var errResp HookErrorResponse
	err := json.Unmarshal(response, &errResp)
	if err != nil {
		return nil, err
	}
	if errResp.Message != "" {
		return &errResp, nil
	}
	return nil, err
}

func ParseMFAVerificationResponse(response []byte) (*MFAVerificationAttemptOutput, error) {
	var MFAVerificationResponse MFAVerificationAttemptOutput
	err := json.Unmarshal(response, &MFAVerificationResponse)
	if err != nil {
		return nil, err
	}

	return &MFAVerificationResponse, err
}

func (ah *AuthHook) FetchHookName() (string, error) {
	// specification for Postgres names
	regExp := `^[a-zA-Z_][a-zA-Z0-9_]{0,62}$`
	re, err := regexp.Compile(regExp)
	if err != nil {
		return "", err
	}

	u, err := url.Parse(ah.ExtensibilityPointConfiguration.URI)
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

func (ah *AuthHook) TriggerPostgresHook() ([]byte, error) {
	// Determine Result payload and request payload
	var hookResponse []byte
	hookName, err := ah.FetchHookName()
	if err != nil {
		return nil, err
	}
	if err := ah.DB.Transaction(func(tx *storage.Connection) error {
		// TODO: add some sort of logging here so that we track that the function is called
		query := tx.RawQuery(fmt.Sprintf("SELECT * from %s(?)", hookName), string(ah.Payload))
		terr := query.First(&hookResponse)
		if terr != nil {
			return terr
		}
		return nil
	}); err != nil {
		return nil, err
	}
	// TODO: Check if it's an error response
	// if errorResponse, err := parseErrorResponse(hookResponse); err != nil {
	// 	if errorResponse != nil {
	// 		return nil, errors.New(errorResponse.ErrorMessage)
	// 	}
	// 	return nil, err
	// }

	return hookResponse, nil

}
