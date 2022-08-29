package models

import (
	"database/sql"
	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/storage"
	"github.com/pkg/errors"
	"time"
)

const FactorPrefix = "factor"

const FactorDisabledState = "disabled"
const FactorUnverifiedState = "unverified"
const FactorVerifiedState = "verified"

const TOTP = "totp"
const Webauthn = "webauthn"

type Factor struct {
	ID           string    `json:"id" db:"id"`
	User         User      `belongs_to:"user"`
	UserID       uuid.UUID `json:"user_id" db:"user_id"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
	Status       string    `json:"status" db:"status"`
	FriendlyName string    `json:"friendly_name" db:"friendly_name"`
	SecretKey    string    `json:"-" db:"secret_key"`
	FactorType   string    `json:"factor_type" db:"factor_type"`
}

func (Factor) TableName() string {
	tableName := "mfa_factors"
	return tableName
}

func NewFactor(user *User, friendlyName, id, factorType, status, secretKey string) (*Factor, error) {
	factor := &Factor{
		UserID:       user.ID,
		ID:           id,
		Status:       status,
		FriendlyName: friendlyName,
		SecretKey:    secretKey,
		FactorType:   factorType,
	}
	return factor, nil
}

// FindFactorsByUser returns all factors belonging to a user ordered by timestamp
func FindFactorsByUser(tx *storage.Connection, user *User) ([]*Factor, error) {
	factors := []*Factor{}
	if err := tx.Q().Where("user_id = ?", user.ID).Order("created_at asc").All(&factors); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return factors, nil
		}
		return nil, errors.Wrap(err, "Error finding mfa factors")
	}
	return factors, nil
}

func FindFactorByFactorID(tx *storage.Connection, factorID string) (*Factor, error) {
	factor, err := findFactor(tx, "id = ?", factorID)
	if err != nil {
		return nil, FactorNotFoundError{}
	}
	return factor, nil
}

func FindFactorByFriendlyName(tx *storage.Connection, friendlyName string) (*Factor, error) {
	factor, err := findFactor(tx, "friendly_name = ?", friendlyName)
	if err != nil {
		return nil, FactorNotFoundError{}
	}
	return factor, nil
}

func findFactor(tx *storage.Connection, query string, args ...interface{}) (*Factor, error) {
	obj := &Factor{}
	if err := tx.Eager().Q().Where(query, args...).First(obj); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, FactorNotFoundError{}
		}
		return nil, errors.Wrap(err, "error finding factor")
	}

	return obj, nil
}

func FindFactorByChallengeID(tx *storage.Connection, challengeID string) (*Factor, error) {
	factor := &Factor{}
	if err := tx.Q().Join("mfa_challenges", "mfa_factors.ID = mfa_challenges.factor_id").Where("mfa_challenges.id= ?", challengeID).First(factor); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, FactorNotFoundError{}
		}
		return nil, errors.Wrap(err, "error finding factor")
	}
	return factor, nil
}

func FindVerifiedFactorsByUser(tx *storage.Connection, user *User) ([]*Factor, error) {
	factors := []*Factor{}
	if err := tx.Q().Where("user_id = ? AND status = ?", user.ID, FactorVerifiedState).All(&factors); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return factors, nil
		}
		return nil, errors.Wrap(err, "Error finding verified mfa factors")
	}
	return factors, nil
}

// Change the friendly name
func (f *Factor) UpdateFriendlyName(tx *storage.Connection, friendlyName string) error {
	f.FriendlyName = friendlyName
	return tx.UpdateOnly(f, "friendly_name", "updated_at")
}

// Change the factor status
func (f *Factor) UpdateStatus(tx *storage.Connection, status string) error {
	f.Status = status
	return tx.UpdateOnly(f, "status", "updated_at")
}

// Checks if MFA is Enabled
func IsMFAEnabled(tx *storage.Connection, user *User) (bool, error) {
	factors, err := FindVerifiedFactorsByUser(tx, user)
	if err != nil {
		return false, err
	}
	if len(factors) >= 1 {
		return true, nil
	}
	return false, nil
}

// Change the factor type
func (f *Factor) UpdateFactorType(tx *storage.Connection, factorType string) error {
	f.FactorType = factorType
	return tx.UpdateOnly(f, "factor_type", "updated_at")
}
