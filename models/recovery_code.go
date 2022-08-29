package models

import (
	"database/sql"
	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/crypto"
	"github.com/netlify/gotrue/storage"
	"github.com/pkg/errors"
	"time"
)

type RecoveryCode struct {
	ID           uuid.UUID  `json:"id" db:"id"`
	UserID       uuid.UUID  `json:"user_id" db:"user_id"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
	RecoveryCode string     `json:"recovery_code" db:"recovery_code"`
	UsedAt       *time.Time `json:"used_at" db:"used_at"`
}

func (RecoveryCode) TableName() string {
	tableName := "mfa_recovery_codes"
	return tableName
}

// Returns a new recovery code associated with the user
func NewRecoveryCode(user *User, recoveryCode string) (*RecoveryCode, error) {
	id, err := uuid.NewV4()
	if err != nil {
		return nil, errors.Wrap(err, "Error generating unique id")
	}
	code := &RecoveryCode{
		ID:           id,
		UserID:       user.ID,
		RecoveryCode: recoveryCode,
	}

	return code, nil
}

// FindValidRecoveryCodes returns all valid recovery codes associated to a user
func FindValidRecoveryCodesByUser(tx *storage.Connection, user *User) ([]*RecoveryCode, error) {
	recoveryCodes := []*RecoveryCode{}
	if err := tx.Q().Where("user_id = ? AND used_at IS NOT NULL", user.ID).All(&recoveryCodes); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return recoveryCodes, nil
		}
		return nil, errors.Wrap(err, "Error finding recovery codes")
	}
	return recoveryCodes, nil
}

// Validate recovery code
func IsRecoveryCodeValid(tx *storage.Connection, user *User, recoveryCode string) (*RecoveryCode, error) {
	rc := &RecoveryCode{}
	if err := tx.Q().Where("user_id = ? AND used_at IS NULL AND recovery_code = ?", user.ID, recoveryCode).First(&rc); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, nil
		}
		return nil, nil
	}
	return rc, nil
}

// Use and invalidate a recovery code
func (r *RecoveryCode) Consume(tx *storage.Connection) error {
	now := time.Now()
	r.UsedAt = &now
	return tx.UpdateOnly(r, "used_at")
}

func GenerateBatchOfRecoveryCodes(tx *storage.Connection, user *User) ([]*RecoveryCode, error) {
	recoveryCodes := []*RecoveryCode{}
	for i := 0; i <= NumRecoveryCodes; i++ {
		rc, err := NewRecoveryCode(user, crypto.SecureToken(RecoveryCodeLength))
		if err = tx.Create(rc); err != nil {
			return nil, errors.Wrap(err, "error creating recovery code")
		}
		recoveryCodes = append(recoveryCodes, rc)
	}
	return recoveryCodes, nil
}

func ValidateRecoveryCode(tx *storage.Connection, user *User, recoveryCode string) error {
	rc, terr := IsRecoveryCodeValid(tx, user, recoveryCode)
	if terr != nil {
		return terr
	}
	if rc.RecoveryCode == recoveryCode {
		terr = rc.Consume(tx)
		if terr != nil {
			return terr
		}
		return nil
	}
	return errors.New("Invalid code entered")

}
