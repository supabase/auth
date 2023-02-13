package models

import (
	"database/sql"
	"github.com/netlify/gotrue/internal/storage"
	"github.com/pkg/errors"
	"time"

	"github.com/gofrs/uuid"
)

type OAuthState struct {
	ID                  uuid.UUID `json:"id" db:"id"`
	AuthCode            string    `json:"auth_code" db:"auth_code"`
	HashedCodeChallenge string    `json:"hashed_code_challenge" db:"hashed_code_challenge"`
	ProviderType        string    `json:"provider_type" db:"provider_type"`
	RedirectURI         string    `json:"redirect_uri" db:"redirect_uri"`
	CreatedAt           time.Time `json:"created_at" db:"created_at"`
	UpdatedAt           time.Time `json:"updated_at" db:"updated_at"`
}

func (OAuthState) TableName() string {
	tableName := "oauth_state"
	return tableName
}

func NewOAuthState(providerType, hashedChallenge string) (*OAuthState, error) {
	id, err := uuid.NewV4()
	if err != nil {
		return nil, errors.New("error generating unique oauth state verifier")
	}
	oauth := &OAuthState{
		ID:                  id,
		ProviderType:        providerType,
		HashedCodeChallenge: hashedChallenge,
		// TODO(Joel): Consider reinstating authcode and redirect uri
	}
	return oauth, nil
}

func FindOAuthStateByAuthCode(tx *storage.Connection, authCode string) (*OAuthState, error) {
	obj := &OAuthState{}
	if err := tx.Eager().Q().Where("auth_code = ?", authCode).First(obj); err != nil {
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
