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
	VerifiedAt   *time.Time `json:"verified_at" db:"verified_at"`
	UsedAt       *time.Time `json:"-" db:"used_at"`
}

const NumRecoveryCodes = 8
const RecoveryCodeLength = 12

func (RecoveryCode) TableName() string {
	tableName := "mfa_recovery_codes"
	return tableName
}

// Returns a new recovery code associated with the user
func NewRecoveryCode(user *User, recoveryFactorID uuid.UUID, recoveryCode string) (*RecoveryCode, error) {
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

	if err := tx.Q().Where("factor_id = ? AND used_at IS NOT NULL", factor.ID).All(&recoveryCodes); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return recoveryCodes, nil
		}
		return nil, errors.Wrap(err, "Error finding recovery codes")
	}
	return recoveryCodes, nil
}

// Validate recovery code
func FindMatchingRecoveryCode(tx *storage.Connection, user *User, recoveryCode string) (*RecoveryCode, error) {
	rc := &RecoveryCode{}

	recoveryFactor, err := user.RecoveryFactor()
	if err != nil {
		return nil, err
	}
	if recoveryFactor == nil {
		return nil, errors.New("user does not have recovery factor")
	}

	if err := tx.Q().Where("factor_id = ? AND used_at is null AND recovery_code = ? AND verified_at is not null", recoveryFactor.ID, recoveryCode).First(&rc); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return rc, errors.New("no matching recovery code")
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
	if factor.FactorType != Recovery {
		return nil, errors.New("recovery factor required to generate codes")
	}
	recoveryCodes := []*RecoveryCode{}
	// TODO(Joel): Convert this into invalidate recovery code for factor
	if err := InvalidateRecoveryCodesForFactor(tx, factor); err != nil {
		return nil, err
	}

	for i := 0; i <= NumRecoveryCodes; i++ {
		rc, err := NewRecoveryCode(user, factor.ID, crypto.SecureToken(RecoveryCodeLength))
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

func ValidateRecoveryCode(tx *storage.Connection, user *User, recoveryCode string) error {
	rc, terr := FindMatchingRecoveryCode(tx, user, recoveryCode)
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
