package models

import (
	"github.com/gobuffalo/pop/v5"
	"time"

	"github.com/gofrs/uuid"
)

type CryptoAddress struct {
	InstanceID uuid.UUID `json:"-" db:"instance_id"`
	ID         uuid.UUID `json:"id" db:"id"`

	AccountId uuid.UUID `json:"account_id" db:"account_id"`
	Address   string    `json:"address" db:"address"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

func (CryptoAddress) TableName() string {
	tableName := "crypto_addresses"
	return tableName
}

// BeforeCreate is invoked before a create operation is ran
func (c *CryptoAddress) BeforeCreate(tx *pop.Connection) error {
	return c.BeforeUpdate(tx)
}

// BeforeUpdate is invoked before an update operation is ran
func (c *CryptoAddress) BeforeUpdate(tx *pop.Connection) error {
	return nil
}

// BeforeSave is invoked before the nonce is saved to the database
func (c *CryptoAddress) BeforeSave(tx *pop.Connection) error {
	return nil
}
