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
	ID           uuid.UUID  `json:"-" db:"id"`
	FactorID     uuid.UUID  `json:"-" db:"factor_id"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
	RecoveryCode string     `json:"recovery_code" db:"recovery_code"`
	UsedAt       *time.Time `json:"-" db:"used_at"`
}

const NumRecoveryCodes = 8
const RecoveryCodeLength = 12

func (RecoveryCode) TableName() string {
	tableName := "mfa_recovery_codes"
	return tableName
}

func NewRecoveryCode(recoveryFactorID uuid.UUID, recoveryCode string) (*RecoveryCode, error) {
	id, err := uuid.NewV4()
	if err != nil {
		return nil, errors.Wrap(err, "Error generating unique id")
	}
	code := &RecoveryCode{
		ID:           id,
		FactorID:     recoveryFactorID,
		RecoveryCode: recoveryCode,
	}

	return code, nil
}

// FindValidRecoveryCodes returns all valid recovery codes associated to a factor
func FindValidRecoveryCodesByFactor(tx *storage.Connection, factor *Factor) ([]*RecoveryCode, error) {
	recoveryCodes := []*RecoveryCode{}

	if err := tx.Q().Where("factor_id = ? AND used_at is null", factor.ID).All(&recoveryCodes); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return recoveryCodes, nil
		}
		return nil, errors.Wrap(err, "Error finding recovery codes")
	}
	return recoveryCodes, nil
}

// Validate recovery code
func FindMatchingRecoveryCode(tx *storage.Connection, factor *Factor, recoveryCode string) (*RecoveryCode, error) {
	if factor.FactorType != Recovery {
		return nil, errors.New("factor needs to be recovery factor to use recovery code")
	}
	rc := &RecoveryCode{}
	if err := tx.Q().Where("factor_id = ? AND recovery_code = ? AND used_at is  null", factor.ID, recoveryCode).First(rc); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return rc, RecoveryCodeNotFoundError{}
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

func InvalidateRecoveryCodesForUser(tx *storage.Connection, user *User) error {
	factors, err := FindFactorsByUser(tx, user)
	if err != nil {
		return err
	}
	// This is an n+1 query?
	for _, factor := range factors {
		if factor.FactorType == Recovery {
			err = InvalidateRecoveryCodesForFactor(tx, factor)
			if err != nil {
				return err
			}
		}
	}
	return nil

}

func InvalidateRecoveryCodesForFactor(tx *storage.Connection, factor *Factor) error {
	recoveryCodes, err := FindValidRecoveryCodesByFactor(tx, factor)
	if err != nil {
		return err
	}
	for _, recoveryCode := range recoveryCodes {
		err = recoveryCode.Consume(tx)
		if err != nil {
			return err
		}
	}
	return nil
}

func GenerateBatchOfRecoveryCodes(tx *storage.Connection, user *User, factor *Factor) ([]*RecoveryCode, error) {
	recoveryCodes := []*RecoveryCode{}
	if err := InvalidateRecoveryCodesForUser(tx, user); err != nil {
		return nil, err
	}

	for i := 0; i <= NumRecoveryCodes; i++ {
		rc, err := NewRecoveryCode(factor.ID, crypto.SecureToken(RecoveryCodeLength))
		if err != nil {
			return nil, err
		}
		if err = tx.Create(rc); err != nil {
			return nil, errors.Wrap(err, "error creating recovery code")
		}

		recoveryCodes = append(recoveryCodes, rc)
	}
	return recoveryCodes, nil
}
