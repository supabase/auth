package api

import (
	"encoding/json"
	"time"

	"github.com/gofrs/uuid"
	"github.com/supabase/gotrue/internal/conf"
)

type HookType string

const (
	PostgresHook HookType = "postgres"
)

type AuthHook struct {
	*conf.HookConfiguration
	payload  []byte
	hookType HookType
	event    string
}

// Hook Events
const (
	MFAVerificationEvent = "auth.mfa_verfication"
)

const (
	defaultTimeout     = time.Second * 2
	defaultHookRetries = 3
)

// Functions for encoding and decoding payload
func CreateMFAVerificationHookInput(user_id uuid.UUID, factor_id uuid.UUID, valid bool) ([]byte, error) {
	// TODO: find a better way of encdoing so we can support HTTP hooks
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

func (a *AuthHook) Trigger() ([]byte, error) {
	// Parse URI object

	// switch between Postgres Hook and HTTP Hook, pass in URI
	return nil, nil
}

func (a *AuthHook) triggerPostgresHook() error {

	return nil
}
