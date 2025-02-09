package provider

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/crypto"
	"github.com/supabase/auth/internal/storage"
	siws "github.com/supabase/auth/internal/utilities/solana"
	"golang.org/x/oauth2"
)

const (
	BlockchainEthereum = "ethereum"
	BlockchainSolana   = "solana"
)

// Web3Provider implements Web3 authentication following EIP-4361 spec
type Web3Provider struct {
	config       conf.Web3Configuration
	chains       map[string]conf.BlockchainConfig
	defaultChain string
}

type Web3GrantParams struct {
	Message   string `json:"message"`
	Signature string `json:"signature"`
	Chain     string `json:"chain"`
}

func NewWeb3Provider(ctx context.Context, config conf.Web3Configuration) (*Web3Provider, error) {
	if !config.Enabled {
		return nil, errors.New("Web3 provider is not enabled")
	}

	// Parse chains
	chains, err := config.ParseSupportedChains()
	if err != nil {
		return nil, err
	}

	// Validate default chain
	if config.DefaultChain != "" {
		if _, ok := chains[config.DefaultChain]; !ok {
			return nil, fmt.Errorf("default chain %s not in supported chains", config.DefaultChain)
		}
	}

	return &Web3Provider{
		config:       config,
		chains:       chains,
		defaultChain: config.DefaultChain,
	}, nil
}

func (p *Web3Provider) AuthCodeURL(state string, args ...oauth2.AuthCodeOption) string {
	return "" // Web3 auth doesn't use OAuth flow
}

func (p *Web3Provider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return nil, errors.New("GetOAuthToken not implemented for Web3")
}

func (p *Web3Provider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	return nil, errors.New("GetUserData not implemented for Web3")
}

// VerifySignedMessage verifies a signed Web3 message based on the blockchain
func (p *Web3Provider) VerifySignedMessage(db *storage.Connection, params *Web3GrantParams) (*UserProvidedData, error) {   
	var err error
	
	parsedMessage, err := siws.ParseSIWSMessage(params.Message)

	if err != nil {
		return nil, siws.ErrorMalformedMessage
	}


	// Verify and consume nonce first
	if err := crypto.VerifyAndConsumeNonce(db, parsedMessage.Nonce, parsedMessage.Address); err != nil {
		return nil, siws.ErrorCodeInvalidNonce
	}
	network := strings.Split(params.Chain, ":")
	if len(network) != 2 {
		return nil, siws.ErrInvalidChainID
	}
	chain := network[0]
	if chain == "" {
		return nil, siws.ErrInvalidChainID
	}
	
	switch chain {
	case BlockchainEthereum:
		return nil, httpError(http.StatusNotImplemented, "signature verification not implemented for %s", network)
		
	case BlockchainSolana:
		err = p.verifySolanaSignature(params.Signature, params.Message, parsedMessage)
	default:
		return nil, httpError(http.StatusNotImplemented, "signature verification not implemented for %s", network)
	}

	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// Construct the provider_id as network:chain:address to make it unique
	providerId := fmt.Sprintf("%s:%s", params.Chain, parsedMessage.Address)

	return &UserProvidedData{
		Metadata: &Claims{
			CustomClaims: map[string]interface{}{
				"address": parsedMessage.Address,
				"chain":   parsedMessage.ChainID,
				"role":    "authenticated",
			},
			Subject: providerId, // This becomes the provider_id in the identity
		},
		Emails: []Email{},
	}, nil
}


func (p *Web3Provider) verifySolanaSignature(signature string, rawMessage string, msg *siws.SIWSMessage) error {
	// Decode base64 signature into bytes
	sigBytes, err := base64.StdEncoding.DecodeString(string(signature))
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}

	params := siws.SIWSVerificationParams{
		ExpectedDomain: p.config.Domain,
		CheckTime:      true,
		TimeDuration:   p.config.Timeout,
	}

	if err := crypto.VerifySIWS(rawMessage, sigBytes, msg, params); err != nil {
		return err
	}

	return nil
}

func (p *Web3Provider) GenerateSignMessage(address string, chain string, uri string) (string, error) {
	if chain == "" {
		chain = p.defaultChain
	}

	chainCfg, ok := p.chains[chain]
	if !ok {
		return "", fmt.Errorf("unsupported chain: %s", chain)
	}

	// Generate nonce for message uniqueness
	nonce := crypto.SecureAlphanumeric(12)

	now := time.Now().UTC()

	switch chainCfg.NetworkName {
	case BlockchainSolana:
		msg := siws.SIWSMessage{
			Domain:    p.config.Domain,
			Address:   address,
			Statement: p.config.Statement,
			URI:       uri,
			Version:   p.config.Version,
			Nonce:     nonce,
			IssuedAt:  now,
		}
		return siws.ConstructMessage(msg), nil

	case BlockchainEthereum:
		return fmt.Sprintf(`%s wants you to sign in with your %s account:
%s

URI: %s
Version: %s
Chain ID: %s
Nonce: %d
Issued At: %s
Expiration Time: %s`,
			p.config.Domain,
			chainCfg.NetworkName,
			address,
			uri,
			p.config.Version,
			chainCfg.ChainID,
			now.UnixNano(),
			now.Format(time.RFC3339),
			now.Add(p.config.Timeout).Format(time.RFC3339)), nil

	default:
		return "", fmt.Errorf("message generation not implemented for %s", chainCfg.NetworkName)
	}
}

