package models

import (
	"database/sql"
	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/storage"
	"github.com/pkg/errors"
	"time"
)

type Factor struct {
	UserID           uuid.UUID `json`
	ID               string    `json:"id" db:"id"`
	CreatedAt        time.Time `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time `json:"updated_at" db:"updated_at"`
	Enabled          bool      `json:"enabled" db:"enabled"`
	FactorSimpleName string    `json:"factor_simple_name" db:"factor_simple_name"`
	SecretKey        string    `json:'-' db:'secret_key'`
	FactorType       string    `json:"factor_type" db:"factor_type"`
}

func (Factor) TableName() string {
	tableName := "mfa_factors"
	return tableName
}

func NewFactor(user *User, factorSimpleName, id, factorType, secretKey string) (*Factor, error) {
	// TODO: Pass in secret and hash it using bcrypt or equiv
	factor := &Factor{
		ID:               id,
		UserID:           user.ID,
		Enabled:          true,
		FactorSimpleName: factorSimpleName,
		SecretKey:        secretKey,
		FactorType:       factorType,
	}
	return factor, nil
}

// FindFactorsByUser returns all factors belonging to a user
func FindFactorsByUser(tx *storage.Connection, user *User) ([]*Factor, error) {
	factors := []*Factor{}
	if err := tx.Q().Where("user_id = ?", user.ID, true).All(&factors); err != nil {
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

func FindFactorBySimpleName(tx *storage.Connection, simpleName string) (*Factor, error) {
	factor, err := findFactor(tx, "factor_simple_name = ?", simpleName)
	if err != nil {
		return nil, FactorNotFoundError{}
	}
	return factor, nil
}

func FindFactorByChallengeID(tx *storage.Connection, factorID string) (*Factor, error) {
	factor := &Factor{}
	if err := tx.Q().Join("mfa_challenges", "mfa_factors.ID = mfa_challenges.factor_id").Where("id = ?", factorID).First(factor); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, FactorNotFoundError{}
		}
		return nil, errors.Wrap(err, "error finding factor")
	}
	return factor, nil
}

// Change the factor simple name
func (f *Factor) UpdateFactorSimpleName(tx *storage.Connection) error {
	f.UpdatedAt = time.Now()
	return tx.UpdateOnly(f, "factor_simple_name", "updated_at")
}

func (f *Factor) Disable(tx *storage.Connection) error {
	f.Enabled = false
	return tx.UpdateOnly(f, "enabled")
}

func (f *Factor) Enable(tx *storage.Connection) error {
	f.Enabled = true
	return tx.UpdateOnly(f, "enabled")
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
