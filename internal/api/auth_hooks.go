package api

import (
	"encoding/json"
	"errors"
	"net/url"

	"fmt"
	"github.com/gofrs/uuid"
	"github.com/supabase/gotrue/internal/conf"
	"github.com/supabase/gotrue/internal/storage"
	"strings"
)

type HookType string

const (
	PostgresHook HookType = "postgres"
	HTTPHook     HookType = "http"
)

type AuthHook struct {
	*conf.ExtensibilityPointConfiguration
	payload  []byte
	hookType HookType
	event    string
	db       *storage.Connection
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

type MFAVerificationHookResponse struct {
	Decision string `json:"decision"`
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

func parseMFAVerificationResponse(response []byte) (*MFAVerificationHookResponse, error) {
	var MFAVerificationResponse MFAVerificationHookResponse
	err := json.Unmarshal(response, &MFAVerificationResponse)
	if err != nil {
		return nil, err
	}

	return &MFAVerificationResponse, err
}

// Functions for encoding and decoding payload
func CreateMFAVerificationHookInput(user_id uuid.UUID, factor_id uuid.UUID, valid bool) ([]byte, error) {
	payload := struct {
		UserID   uuid.UUID `json:"user_id"`
		FactorID uuid.UUID `json:"factor_id"`
		Valid    bool      `json:"valid"`
	}{
		UserID:   user_id,
		FactorID: factor_id,
		Valid:    valid,
	}
	data, err := json.Marshal(&payload)
	if err != nil {
		return nil, err
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
	case string(HTTPHook):
		return ah.triggerHTTPHook()
	default:
		return nil, errors.New("unsupported hook type")
	}

	return nil, nil
}

func (ah *AuthHook) fetchHookName() (string, error) {
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
	// TODO: maybe enforce checks on this name?

	return schema + "." + table, nil
}

func (ah *AuthHook) triggerPostgresHook() ([]byte, error) {
	// Determine Result payload and request payload
	var result []byte
	hookName, err := ah.fetchHookName()
	if err != nil {
		return nil, err
	}
	if err := ah.db.Transaction(func(tx *storage.Connection) error {
		resp := tx.RawQuery(fmt.Sprintf("SELECT %s('%s')", hookName, ah.payload))
		terr := resp.First(result)
		if terr != nil {
			return terr
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return result, nil

}

func (a *AuthHook) triggerHTTPHook() ([]byte, error) {
	return nil, errors.New("not implemented error")
}
