package models

import (
	"database/sql"
	"time"

	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"github.com/supabase/auth/internal/storage"
)

const OAuthStateTimeout = 5 * time.Minute

type OAuthState struct {
	ID           uuid.UUID `json:"id" db:"id"`
	ProviderType string    `json:"provider_type" db:"provider_type"`
	CodeVerifier *string   `json:"code_verifier,omitempty" db:"code_verifier"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
}

func (OAuthState) TableName() string {
	return "oauth_states"
}

func NewOAuthState(providerType string, codeVerifier *string) *OAuthState {
	return &OAuthState{
		ID:           uuid.Must(uuid.NewV4()),
		ProviderType: providerType,
		CodeVerifier: codeVerifier,
	}
}

func FindOAuthStateByID(tx *storage.Connection, id uuid.UUID) (*OAuthState, error) {
	obj := &OAuthState{}
	if err := tx.Q().Where("id = ?", id).First(obj); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, OAuthStateNotFoundError{}
		}
		return nil, errors.Wrap(err, "error finding oauth state")
	}
	return obj, nil
}

func (s *OAuthState) IsExpired() bool {
	return time.Since(s.CreatedAt) > OAuthStateTimeout
}
