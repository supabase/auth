package models

import (
	"database/sql"
	"github.com/gobuffalo/pop/v5"
	"github.com/netlify/gotrue/storage"
	"github.com/pkg/errors"
	"time"

	"github.com/gofrs/uuid"
)

type CryptoAddress struct {
	InstanceID uuid.UUID `json:"-" db:"instance_id"`
	ID         uuid.UUID `json:"id" db:"id"`

	AccountId uuid.UUID `json:"account_id" db:"account_id"`
	Address   string    `json:"address" db:"address"`
	Provider  string    `json:"provider" db:"provider"`

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

func NewCryptoAddress(instanceID uuid.UUID, accountId uuid.UUID, provider string, caipString string) (*CryptoAddress, error) {
	id, err := uuid.NewV4()
	if err != nil {
		return nil, errors.Wrap(err, "Error generating unique id")
	}

	address := &CryptoAddress{
		InstanceID: instanceID,
		ID:         id,
		AccountId:  accountId,
		Address:    caipString,
		Provider:   provider,
		CreatedAt:  time.Now().UTC(),
	}

	return address, nil
}

func GetCryptoAddressByAddress(tx *storage.Connection, address string) (*CryptoAddress, error) {
	nonce := CryptoAddress{}
	if err := tx.Where("address = ?", address).First(&nonce); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, CryptoAddressNotFoundError{}
		}
		return nil, errors.Wrap(err, "error finding crypto address")
	}
	return &nonce, nil
}

func GetCryptoAddressById(tx *storage.Connection, id uuid.UUID) (*CryptoAddress, error) {
	nonce := CryptoAddress{}
	if err := tx.Where("id = ?", id).First(&nonce); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, CryptoAddressNotFoundError{}
		}
		return nil, errors.Wrap(err, "error finding crypto address")
	}
	return &nonce, nil
}
