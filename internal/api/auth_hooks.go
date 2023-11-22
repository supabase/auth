package api

import (
	"encoding/json"
	"errors"
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
	payload                         []byte
	hookType                        HookType
	event                           string
	db                              *storage.Connection
}

// Hook Events
const (
	MFAVerificationEvent = "auth.mfa_verfication"
)

type HookErrorResponse struct {
	ErrorMessage string `json:"error_message"`
	ErrorCode    string `json:"error_code"`
	RetryAfter   bool   `json:"retry_after"`
}

func parseErrorResponse(response []byte) (*HookErrorResponse, error) {
	var errResp HookErrorResponse
	err := json.Unmarshal(response, &errResp)
	if err != nil {
		return nil, err
	}
	if errResp.ErrorMessage != "" {
		return &errResp, nil
	}
	return nil, err
}

func parseMFAVerificationResponse(response []byte) (*MFAVerificationHookOutput, error) {
	var MFAVerificationResponse MFAVerificationHookOutput
	err := json.Unmarshal(response, &MFAVerificationResponse)
	if err != nil {
		return nil, err
	}

	return &MFAVerificationResponse, err
}

type MFAVerificationHookInput struct {
	UserID   uuid.UUID `json:"user_id"`
	FactorID uuid.UUID `json:"factor_id"`
	Valid    bool      `json:"valid"`
}
type MFAVerificationHookOutput struct {
	Decision string `json:"decision"`
}

// Functions for encoding and decoding payload
func CreateMFAVerificationHookInput(user_id uuid.UUID, factor_id uuid.UUID, valid bool) ([]byte, error) {
	payload := MFAVerificationHookInput{
		UserID:   user_id,
		FactorID: factor_id,
		Valid:    valid,
	}
	data, err := json.Marshal(&payload)
	if err != nil {
		panic(err)
	}
	return data, nil
}

func (ah *AuthHook) Trigger() ([]byte, error) {
	// Parse URI object
	url, err := url.Parse(ah.ExtensibilityPointConfiguration.URI)
	if err != nil {
		return nil, err
	}
	// trigger appropriate type of hook
	switch url.Scheme {
	case string(PostgresHook):
		return ah.triggerPostgresHook()
	default:
		return nil, errors.New("unsupported hook type")
	}
}

func (ah *AuthHook) fetchHookName() (string, error) {
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

func (ah *AuthHook) triggerPostgresHook() ([]byte, error) {
	// Determine Result payload and request payload
	var hookResponse []byte
	hookName, err := ah.fetchHookName()
	if err != nil {
		return nil, err
	}
	if err := ah.db.Transaction(func(tx *storage.Connection) error {
		// TODO: add some sort of logging here so that we track that the function is called
		query := tx.RawQuery(fmt.Sprintf("SELECT * from %s(?)", hookName), string(ah.payload))
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
