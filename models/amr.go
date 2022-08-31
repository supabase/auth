package models

import (
	"fmt"
)

type AMRClaim struct {
	ID           uuid.UUID `json:"id" db:"id"`
	SessionID    uuid.UUID `json:"session_id" db:"session_id"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
	SignInMethod string    `json:"sign_in_method" db:"sign_in_method"`
}

func (RecoveryCode) TableName() string {
	tableName := "mfa_amr_claims"
	return tableName
}

func NewAMRClaim(sessionID uuid.UUID, signInMethod string) {
	id, err := uuid.NewV4()
	if err != nil {
		return nil, errors.Wrap(err, "Error generating unique id")
	}
	claim := &AMRClaim{
		ID:        id,
		SessionID: sesionID,
	}

}

func AddClaimToSession(session *Session, signInMethod string) error {
	claim := NewAMRClaim(session.ID, signInMethod)
	return tx.Create(claim)
}

// Finds all Sessions associated to a factor and deletes them
func DeleteClaimsByFactorID(tx *storage.Connection, factorID string, claimType string) error {
	// Join on sessions and calims  Find all fclaims assoicated with a given TOTP factor
}
