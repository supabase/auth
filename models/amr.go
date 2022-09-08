package models

import (
	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/storage"
	"github.com/pkg/errors"
	"time"
)

type AMRClaim struct {
	ID           uuid.UUID `json:"id" db:"id"`
	SessionID    uuid.UUID `json:"session_id" db:"session_id"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
	SignInMethod string    `json:"sign_in_method" db:"sign_in_method"`
}

func (AMRClaim) TableName() string {
	tableName := "mfa_amr_claims"
	return tableName
}

func NewAMRClaim(sessionID uuid.UUID, signInMethod string) (*AMRClaim, error) {
	id, err := uuid.NewV4()
	if err != nil {
		return nil, errors.Wrap(err, "Error generating unique id")
	}
	claim := &AMRClaim{
		ID:           id,
		SessionID:    sessionID,
		SignInMethod: signInMethod,
	}
	return claim, nil

}

func AddClaimToSession(tx *storage.Connection, session *Session, signInMethod string) error {
	claim, err := NewAMRClaim(session.ID, signInMethod)
	if err != nil {
		return err
	}
	return tx.Create(claim)
}

