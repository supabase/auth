package models

import (
	"database/sql"
	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/storage"
	"github.com/pkg/errors"
	"time"
)

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

// FindFactorsByUser returns all factors belonging to a user
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

// Change the friendly name
func (f *Factor) UpdateFriendlyName(tx *storage.Connection, friendlyName string) error {
	f.FriendlyName = friendlyName
	return tx.UpdateOnly(f, "friendly_name", "updated_at")
}

//Change the factor status
func (f *Factor) UpdateStatus(tx *storage.Connection, status string) error {
	f.Status = status
	return tx.UpdateOnly(f, "status", "updated_at")
}
