package models

import (
	"time"

	"github.com/gobuffalo/pop/v5"
	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/crypto"
	"github.com/netlify/gotrue/storage"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

type Nonce struct {
	InstanceID uuid.UUID `json:"-" db:"instance_id"`
	ID         uuid.UUID `json:"id" db:"id"`

	HashedIp string `json:"-" db:"hashed_ip"`
	Nonce    string `json:"nonce" db:"nonce"`

	ConsumedAt *time.Time `json:"consumed_at" db:"consumed_at"`
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
	ExpiresAt  time.Time  `json:"expired_at" db:"expired_at"`
}

func (Nonce) TableName() string {
	tableName := "nonces"
	return tableName
}

func NewNonce(instanceID uuid.UUID, ip string) (*Nonce, error) {
	id, err := uuid.NewV4()
	if err != nil {
		return nil, errors.Wrap(err, "Error generating unique id")
	}

	hashedIp, err := hashIp(ip)
	if err != nil {
		return nil, errors.Wrap(err, "Error hashing IP")
	}

	nonce := &Nonce{
		InstanceID: instanceID,
		ID:         id,
		HashedIp:   hashedIp,
		Nonce:      crypto.SecureToken(),
		ConsumedAt: nil,
		CreatedAt:  time.Now().UTC(),
		ExpiresAt:  time.Now().UTC().Add(time.Minute * 2),
	}

	return nonce, nil
}

// BeforeCreate is invoked before a create operation is ran
func (n *Nonce) BeforeCreate(tx *pop.Connection) error {
	return n.BeforeUpdate(tx)
}

// BeforeUpdate is invoked before an update operation is ran
func (n *Nonce) BeforeUpdate(tx *pop.Connection) error {
	return nil
}

// BeforeSave is invoked before the nonce is saved to the database
func (n *Nonce) BeforeSave(tx *pop.Connection) error {
	if n.ConsumedAt != nil && n.ConsumedAt.IsZero() {
		n.ConsumedAt = nil
	}
	return nil
}

func (n *Nonce) Consume(tx *storage.Connection) error {
	now := time.Now().UTC()
	n.ConsumedAt = &now
	return tx.UpdateOnly(n, "consumed_at")
}

// TODO (HarryET): Look at if this is secure enough or even needed
func hashIp(ip string) (string, error) {
	pw, err := bcrypt.GenerateFromPassword([]byte(ip), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(pw), nil
}

// TODO (HarryET): Look at if this is secure enough or even needed
// Verify nonce was issued to ip
func (n *Nonce) verifyIp(ip string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(n.HashedIp), []byte(ip))
	return err == nil
}
