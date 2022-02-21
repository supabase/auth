package models

import (
	"database/sql"
	"fmt"
	"net/url"
	"time"

	"github.com/gobuffalo/pop/v5"
	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/storage"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

type Nonce struct {
	InstanceID uuid.UUID `json:"-" db:"instance_id"`
	ID         uuid.UUID `json:"id" db:"id"`

	HashedIp string `json:"-" db:"hashed_ip"`

	Url string `json:"url" db:"uri"`

	ChainId        int    `json:"chain_id" db:"chain_id"`
	Address        string `json:"eth_address" db:"eth_address"`
	Cryptocurrency string `json:"cryptocurrency" db:"cryptocurrency"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"`
}

func (Nonce) TableName() string {
	tableName := "nonces"
	return tableName
}

func NewNonce(instanceID uuid.UUID, chainId int, url, walletAddress, cryptocurrency, ip string) (*Nonce, error) {
	id, err := uuid.NewV4()
	if err != nil {
		return nil, errors.Wrap(err, "Error generating unique id")
	}

	hashedIp, err := HashIp(ip)
	if err != nil {
		return nil, errors.Wrap(err, "Error hashing IP")
	}

	nonce := &Nonce{
		InstanceID:     instanceID,
		ID:             id,
		HashedIp:       hashedIp,
		Cryptocurrency: cryptocurrency,
		ChainId:        chainId,
		Address:        walletAddress,
		Url:            url,
		CreatedAt:      time.Now().UTC(),
		ExpiresAt:      time.Now().UTC().Add(time.Minute * 2),
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
	return nil
}

func (n *Nonce) Consume(tx *storage.Connection) error {
	return tx.Destroy(n)
}

func HashIp(ip string) (string, error) {
	pw, err := bcrypt.GenerateFromPassword([]byte(ip), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(pw), nil
}

func (n *Nonce) VerifyIp(ip string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(n.HashedIp), []byte(ip))
	return err == nil
}

func (n *Nonce) Build() (string, error) {
	uri, err := url.Parse(n.Url)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf(`%v wants you to sign in with your Ethereum account:
%v

URI: %v
Version: 1
Nonce: %v
Issued At: %v
Expiration Time: %v
Chain ID: %v`, uri.Hostname(), n.Address, uri.String(), n.CreatedAt.UnixNano()/int64(time.Millisecond), n.CreatedAt.Format(time.RFC3339), n.ExpiresAt.Format(time.RFC3339), n.ChainId), nil
}

func (n *Nonce) BuildWithStatement(statement string) (string, error) {
	uri, err := url.Parse(n.Url)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf(`%v wants you to sign in with your Ethereum account:
%v

%v

URI: %v
Version: 1
Nonce: %v
Issued At: %v
Expiration Time: %v
Chain ID: %v`, uri.Hostname(), n.Address, statement, uri.String(), n.CreatedAt.UnixNano()/int64(time.Millisecond), n.CreatedAt.Format(time.RFC3339), n.ExpiresAt.Format(time.RFC3339), n.ChainId), nil
}

func GetNonceById(tx *storage.Connection, id uuid.UUID) (*Nonce, error) {
	nonce := Nonce{}
	if err := tx.Where("id = ?", id).First(&nonce); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, NonceNotFoundError{}
		}
		return nil, errors.Wrap(err, "error finding nonce")
	}
	return &nonce, nil
}

func GetNonceByWalletAddressAndIp(tx *storage.Connection, walletAddress, hashedIp string) (*Nonce, error) {
	nonce := Nonce{}
	if err := tx.Where("address = ?, hashed_ip = ?", walletAddress, hashedIp).First(&nonce); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, NonceNotFoundError{}
		}
		return nil, errors.Wrap(err, "error finding nonce")
	}
	return &nonce, nil
}
