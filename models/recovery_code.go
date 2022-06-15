package models

import (
	"database/sql"
	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/storage"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
	"time"
)

type RecoveryCode struct {
	UserID       uuid.UUID  `json:"user_id" db:"user_id"`
	CreatedAt    *time.Time `json:"created_at" db:"created_at"`
	RecoveryCode string     `json:"recovery_code" db:"recovery_code"`
	Valid        bool       `json:"valid" db:"valid"`
	TimeUsed     time.Time  `json:"time_used" db:"time_used"`
}

func (RecoveryCode) TableName() string {
	tableName := "recovery_codes"
	return tableName
}

// Returns a new recovery code associated with the user
func NewRecoveryCode(user *User, recoveryCode string, now *time.Time) (*RecoveryCode, error) {
	rc, err := hashRecoveryCode(recoveryCode)
	if err != nil {
		return nil, err
	}

	code := &RecoveryCode{
		UserID:       user.ID,
		RecoveryCode: rc,
		CreatedAt:    now,
		Valid:        true,
	}

	return code, nil
}

// FindRecoveryCodes returns all valid recovery codes associated to a user
func FindRecoveryCodesByUser(tx *storage.Connection, user *User) ([]*RecoveryCode, error) {
	recoveryCodes := []*RecoveryCode{}
	if err := tx.Q().Where("user_id = ? AND valid = ?", user.ID, true).All(&recoveryCodes); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return recoveryCodes, nil
		}
		return nil, errors.Wrap(err, "Error finding recovery codes")
	}
	return recoveryCodes, nil
}

// hashRecoveryCode generates a hashed recoveryCode from a plaintext string
func hashRecoveryCode(recoveryCode string) (string, error) {
	rc, err := bcrypt.GenerateFromPassword([]byte(recoveryCode), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(rc), nil
}
