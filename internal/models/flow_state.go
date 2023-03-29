package models

import (
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"github.com/pkg/errors"
	"github.com/supabase/gotrue/internal/storage"
	"time"

	"github.com/gofrs/uuid"
)

const InvalidCodeChallengeError = "code challenge does not match previously saved code verifier"
const InvalidCodeMethodError = "code challenge method not supported"

type FlowState struct {
	ID                   uuid.UUID  `json:"id" db:"id"`
	UserID               *uuid.UUID `json:"user_id,omitempty" db:"user_id"`
	AuthCode             string     `json:"auth_code" db:"auth_code"`
	CodeChallenge        string     `json:"code_challenge" db:"code_challenge"`
	CodeChallengeMethod  string     `json:"code_challenge_method" db:"code_challenge_method"`
	ProviderType         string     `json:"provider_type" db:"provider_type"`
	ProviderAccessToken  string     `json:"provider_access_token" db:"provider_access_token"`
	ProviderRefreshToken string     `json:"provider_refresh_token" db:"provider_refresh_token"`
	CreatedAt            time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at" db:"updated_at"`
}

type CodeChallengeMethod int

const (
	SHA256 CodeChallengeMethod = iota
	Plain
)

func (authMethod CodeChallengeMethod) String() string {
	switch authMethod {
	case SHA256:
		return "s256"
	case Plain:
		return "plain"
	}
	return ""
}

func (FlowState) TableName() string {
	tableName := "flow_state"
	return tableName
}

func NewFlowState(providerType, codeChallenge string, codeChallengeMethod CodeChallengeMethod) (*FlowState, error) {
	id, err := uuid.NewV4()
	if err != nil {
		return nil, errors.New("error generating unique oauth state verifier")
	}
	authCode := uuid.Must(uuid.NewV4())
	oauth := &FlowState{
		ID:                  id,
		ProviderType:        providerType,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod.String(),
		AuthCode:            authCode.String(),
	}
	return oauth, nil
}

func FindFlowStateByAuthCode(tx *storage.Connection, authCode string) (*FlowState, error) {
	obj := &FlowState{}
	if err := tx.Eager().Q().Where("auth_code = ?", authCode).First(obj); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, FlowStateNotFoundError{}
		}
		return nil, errors.Wrap(err, "error finding oauth state")
	}

	return obj, nil
}

func FindFlowStateByID(tx *storage.Connection, id string) (*FlowState, error) {
	obj := &FlowState{}
	if err := tx.Eager().Q().Where("id = ?", id).First(obj); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, FlowStateNotFoundError{}
		}
		return nil, errors.Wrap(err, "error finding oauth state")
	}

	return obj, nil
}

func (f *FlowState) VerifyPKCE(codeChallenge, codeVerifier string) error {
	switch f.CodeChallengeMethod {
	case SHA256.String():
		hashedCodeVerifier := sha256.Sum256([]byte(codeVerifier))
		encodedCodeVerifier := base64.RawURLEncoding.EncodeToString(hashedCodeVerifier[:])
		if subtle.ConstantTimeCompare([]byte(codeChallenge), []byte(encodedCodeVerifier)) != 1 {
			return errors.New(InvalidCodeChallengeError)
		}
	case Plain.String():
		if subtle.ConstantTimeCompare([]byte(codeChallenge), []byte(codeVerifier)) != 1 {
			return errors.New(InvalidCodeChallengeError)
		}
	default:
		return errors.New(InvalidCodeMethodError)

	}
	return nil
}

func (f *FlowState) IsExpired(expiryDuration time.Duration) bool {
	return f.CreatedAt.After(time.Now().Add(expiryDuration))
}
