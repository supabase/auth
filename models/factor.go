package models

import (
	"database/sql"
	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/storage"
	"github.com/pkg/errors"
	"time"
)

type Factor struct {
	UserID       uuid.UUID `json:"user_id" db:"user_id"`
	ID           string    `json:"id" db:"id"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
	Status       string    `json:"status" db:"status"`
	FriendlyName string    `json:"friendly_name" db:"friendly_name"`
	SecretKey    string    `json:"secret_key" db:"secret_key"`
	FactorType   string    `json:"factor_type" db:"factor_type"`
}

func (Factor) TableName() string {
	tableName := "mfa_factors"
	return tableName
}

func NewFactor(user *User, friendlyName, id, factorType, status, secretKey string) (*Factor, error) {
	// TODO: Pass in secret and hash it using bcrypt or equiv
	factor := &Factor{
		ID:           id,
		UserID:       user.ID,
		Status:       status,
		FriendlyName: friendlyName,
		SecretKey:    secretKey,
		FactorType:   factorType,
	}
	return factor, nil
}

// FindFactorsByUser returns all factors belonging to a user
func FindFactorsByUser(tx *storage.Connection, user *User) ([]*Factor, error) {
	factors := []*Factor{}
	if err := tx.Q().Where("user_id = ?", user.ID).All(&factors); err != nil {
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

// Change the factor simple name
func (f *Factor) UpdateFactorFriendlyName(tx *storage.Connection, friendlyName string) error {
	f.UpdatedAt = time.Now()
	return tx.UpdateOnly(f, "friendly_name", "updated_at")
}

func (f *Factor) UpdateFactorStatus(tx *storage.Connection, status string) error {
	f.Status = status
	return tx.UpdateOnly(f, "status")
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
