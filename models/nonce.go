package models

import (
	"database/sql"
	"fmt"
	"github.com/netlify/gotrue/conf"
	"github.com/spruceid/siwe-go"
	"net/url"
	"time"

	"github.com/gobuffalo/pop/v5"
	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/storage"
	"github.com/pkg/errors"
)

type Nonce struct {
	InstanceID uuid.UUID `json:"-" db:"instance_id"`
	ID         uuid.UUID `json:"id" db:"id"`

	Url      string `json:"url" db:"uri"`
	Hostname string `json:"hostname" db:"hostname"`

	ChainId   string `json:"chain_id" db:"chain_id"`
	Address   string `json:"address" db:"address"`
	Namespace string `json:"namespace" db:"namespace"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"`
}

func (Nonce) TableName() string {
	tableName := "nonces"
	return tableName
}

func NewNonce(instanceID uuid.UUID, chainId, url, hostname, walletAddress, namespace string) (*Nonce, error) {
	id, err := uuid.NewV4()
	if err != nil {
		return nil, errors.Wrap(err, "Error generating unique id")
	}

	nonce := &Nonce{
		InstanceID: instanceID,
		ID:         id,
		Namespace:  namespace,
		ChainId:    chainId,
		Address:    walletAddress,
		Url:        url,
		Hostname:   hostname,
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
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
	return nil
}

func (n *Nonce) Consume(tx *storage.Connection) error {
	return tx.Destroy(n)
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

func (n *Nonce) ToMessage(config *conf.GlobalConfiguration) *siwe.Message {
	messageOptions := siwe.InitMessageOptions(map[string]interface{}{
		"statement":      config.External.Eth.Message,
		"issuedAt":       n.UpdatedAt,
		"nonce":          siwe.GenerateNonce(),
		"chainId":        n.ChainId,
		"expirationTime": n.ExpiresAt,
	})
	message := siwe.InitMessage(n.Hostname, n.Address, n.Url, "1", *messageOptions)
	return message
}

func (n *Nonce) GetCaipAddress() string {
	return fmt.Sprintf("%s:%s:%s", n.Namespace, n.ChainId, n.Address)
}

// TODO (HarryET): Fix queries!
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

func GetNonceByWalletAddress(tx *storage.Connection, walletAddress string) (*Nonce, error) {
	nonce := Nonce{}
	if err := tx.Where("address = ?", walletAddress).First(&nonce); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, NonceNotFoundError{}
		}
		return nil, errors.Wrap(err, "error finding nonce")
	}
	return &nonce, nil
}
