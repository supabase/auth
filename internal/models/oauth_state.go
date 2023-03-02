package models

import (
	"database/sql"
	"github.com/pkg/errors"
	"github.com/supabase/gotrue/internal/storage"
	"time"

	"github.com/gofrs/uuid"
)

type OAuthState struct {
	ID                   uuid.UUID `json:"id" db:"id"`
	SupabaseAuthCode     string    `json:"supabase_auth_code" db:"supabase_auth_code"`
	CodeChallenge        string    `json:"code_challenge" db:"code_challenge"`
	ProviderType         string    `json:"provider_type" db:"provider_type"`
	ProviderAccessToken  string    `json:"provider_access_token" db:"provider_access_token"`
	ProviderRefreshToken string    `json:"provider_refresh_token" db:"provider_refresh_token"`
	CreatedAt            time.Time `json:"created_at" db:"created_at"`
	UpdatedAt            time.Time `json:"updated_at" db:"updated_at"`
}

func (OAuthState) TableName() string {
	tableName := "oauth_state"
	return tableName
}

func NewOAuthState(providerType, codeChallenge string) (*OAuthState, error) {
	id, err := uuid.NewV4()
	if err != nil {
		return nil, errors.New("error generating unique oauth state verifier")
	}
	oauth := &OAuthState{
		ID:            id,
		ProviderType:  providerType,
		CodeChallenge: codeChallenge,
	}
	return oauth, nil
}

func FindOAuthStateByAuthCode(tx *storage.Connection, supabaseAuthCode string) (*OAuthState, error) {
	obj := &OAuthState{}
	if err := tx.Eager().Q().Where("supabase_auth_code = ?", supabaseAuthCode).First(obj); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, OAuthStateNotFoundError{}
		}
		return nil, errors.Wrap(err, "error finding user")
	}

	return obj, nil
}

func FindOAuthStateByID(tx *storage.Connection, id string) (*OAuthState, error) {
	obj := &OAuthState{}
	if err := tx.Eager().Q().Where("id= ?", id).First(obj); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, OAuthStateNotFoundError{}
		}
		return nil, errors.Wrap(err, "error finding user")
	}

	return obj, nil
}
