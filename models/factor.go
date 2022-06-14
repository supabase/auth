package models

import (
	"time"
	"github.com/netlify/gotrue/storage"
	"github.com/pkg/errors"
	"database/sql"
	"github.com/gofrs/uuid"
)

type Factor struct {
	UserID uuid.UUID `json`
	ID string `json:"id" db:"id"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
	Enabled bool `json:"enabled" db:"enabled"`
	FactorSimpleName string `json:"factor_simple_name" db:"factor_simple_name"`
	SecretKey string `json:'secret_key' db:'secret_key'`
	// TODO(Joel): Convert this to an enum
	FactorType string `json:"factor_type" db:"factor_type"`
}

func (Factor) TableName() string {
	tableName :="mfa_factors"
	return tableName
}


func NewFactor(user *User, factorSimpleName, id,factorType, secretKey string)(*Factor, error) {
	// TODO: Pass in secret and hash it using bcrypt or equiv
	factor := &Factor {
		ID: id,
		UserID: user.ID,
		Enabled: true,
		FactorSimpleName: factorSimpleName,
		SecretKey: secretKey,
		FactorType: factorType,

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


// Change the factor simple name
func (f *Factor) UpdateFactorSimpleName(tx *storage.Connection) error {
	f.UpdatedAt = time.Now()
	return tx.UpdateOnly(f, "factor_simple_name", "updated_at")
}

func (f* Factor) Disable(tx *storage.Connection) error {
	f.Enabled = false
	return tx.UpdateOnly(f, "enabled")
}

func (f* Factor) Enable(tx *storage.Connection) error {
	f.Enabled = true
	return tx.UpdateOnly(f, "enabled")
}

// func (f* Factor) FindFactorBySimpleName(tx *storage.Connection) error {

// }

// func (f* Factor) FindFactorById(tx *storage.Connection) error {

// }
