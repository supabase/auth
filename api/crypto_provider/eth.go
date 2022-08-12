package crypto_provider

import (
	"fmt"
	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/conf"
	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
	"github.com/spruceid/siwe-go"
	"net/http"
	"net/url"
	"strconv"
)

type EthProvider struct {
	config *conf.EthProviderConfiguration
}

var _ CryptoProvider = (*EthProvider)(nil)

func NewEthProvider(config *conf.EthProviderConfiguration) (*EthProvider, error) {
	return &EthProvider{
		config: config,
	}, nil
}

func (e *EthProvider) RequiresNonce() bool {
	return true
}

func (e *EthProvider) GenerateNonce(req *http.Request, instanceId uuid.UUID, options CryptoNonceOptions) (*models.Nonce, error) {
	uri, err := url.Parse(options.Url)

	if err != nil {
		return nil, err
	}

	if options.ChainId == nil {
		return nil, fmt.Errorf("eth provider requires a `chain_id` be provided")
	}

	return models.NewNonce(instanceId, *options.ChainId, "eth", uri.String(), uri.Hostname(), options.WalletAddress, "eip155")
}

func (e *EthProvider) BuildNonce(n *models.Nonce) (string, error) {
	msg, err := e.toSiweMessage(n)

	if err != nil {
		return "", err
	}
	
	return msg.String(), nil
}

func (e *EthProvider) ValidateNonce(nonce *models.Nonce, signature string) (bool, error) {
	nonceMessage, err := e.toSiweMessage(nonce)
	if err != nil {
		return false, err
	}

	_, err = nonceMessage.Verify(signature, &nonce.Hostname, &nonce.Nonce, nil)
	if err != nil {
		return false, err
	}

	return true, nil
}

// Used internally to convert to a SIWE message
func (e *EthProvider) toSiweMessage(n *models.Nonce) (*siwe.Message, error) {
	return siwe.InitMessage(n.Hostname, n.Address, n.Url, "1", map[string]interface{}{
		"statement":      e.config.Message,
		"issuedAt":       n.UpdatedAt,
		"nonce":          n.Nonce,
		"chainId":        strconv.Itoa(n.ChainId),
		"expirationTime": n.ExpiresAt,
	})
}

func (e *EthProvider) FetchUser(tx *storage.Connection, instanceId uuid.UUID, aud string, nonce *models.Nonce) (*models.User, error) {
	// Because we have the address in the nonce we can just request the using that address
	return models.FindUserByCryptoAddressAndAudience(tx, instanceId, nonce.Address, aud)
}

func (e *EthProvider) FetchAccountInformation(nonce *models.Nonce) (*CryptoAccountInformation, error) {
	// Eth Provider has the address in the nonce, so it can just be returned
	return &CryptoAccountInformation{
		Address: nonce.Address,
	}, nil
}
