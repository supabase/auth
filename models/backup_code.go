package models

import (
	"database/sql"
	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/storage"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
	"time"
)

type BackupCode struct {
	UserID     uuid.UUID  `json:"user_id" db:"user_id"`
	CreatedAt  *time.Time `json:"created_at" db:"created_at"`
	BackupCode string     `json:"backup_code" db:"backup_code"`
	Valid      bool       `json:"valid" db:"valid"`
	TimeUsed   time.Time  `json:"time_used" db:"time_used"`
}

func (BackupCode) TableName() string {
	tableName := "backup_codes"
	return tableName
}

// Returns a new backupcode associated with the user
func NewBackupCode(user *User, backupCode string, now *time.Time) (*BackupCode, error) {
	bc, err := hashBackupCode(backupCode)
	if err != nil {
		return nil, err
	}

	code := &BackupCode{
		UserID:     user.ID,
		BackupCode: bc,
		CreatedAt:  now,
		Valid:      true,
	}

	return code, nil
}

// FindBackupCodesByUser returns all valid backup codes associated to a user
func FindBackupCodesByUser(tx *storage.Connection, user *User) ([]*BackupCode, error) {
	backupCodes := []*BackupCode{}
	if err := tx.Q().Where("user_id = ? AND valid = ?", user.ID, true).All(&backupCodes); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return backupCodes, nil
		}
		return nil, errors.Wrap(err, "Error finding backup codes")
	}
	return backupCodes, nil
}

// hashBackupCodes generates a hashed backupCoed from a plaintext string
func hashBackupCode(backupCode string) (string, error) {
	bc, err := bcrypt.GenerateFromPassword([]byte(backupCode), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(bc), nil
}
