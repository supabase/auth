package crypto_provider

import (
	"fmt"
	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/conf"
	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
	"net/http"
	"strings"
)

type CryptoAccountInformation struct {
	Address string `json:"address"`
}

type CryptoNonceOptions struct {
	WalletAddress string `json:"wallet_address"` // Hex Encoded
	Url           string `json:"url"`
	// Option as only used by EVM
	ChainId *string `json:"chain_id"`
}

type CryptoProvider interface {
	// RequiresNonce Used to skip nonces for crypto providers that don't use nonces
	RequiresNonce() bool

	// GenerateNonce Generate the nonce model for the provider
	GenerateNonce(req *http.Request, instanceId uuid.UUID, options CryptoNonceOptions) (*models.Nonce, error)
	// BuildNonce Build the nonce into a string
	BuildNonce(nonce *models.Nonce) (string, error)
	// ValidateNonce Validate the nonce against a signature
	ValidateNonce(nonce *models.Nonce, signature string) (bool, error)

	// FetchUser Fetch the user for a nonce
	FetchUser(tx *storage.Connection, instanceId uuid.UUID, aud string, nonce *models.Nonce) (*models.User, error)

	// FetchAccountInformation Fetch account information for a new account
	FetchAccountInformation(nonce *models.Nonce) (*CryptoAccountInformation, error)
}

func GetCryptoProvider(config *conf.Configuration, name string) (CryptoProvider, error) {
	name = strings.ToLower(name)

	switch name {
	case "eth":
		return NewEthProvider(&config.External.Eth)
	default:
		return nil, fmt.Errorf("crypto provider %s could not be found", name)
	}
}
