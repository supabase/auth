package provider

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/crypto"
	"github.com/supabase/auth/internal/storage"
	siws "github.com/supabase/auth/internal/utilities/solana"
	"golang.org/x/oauth2"
)

const (
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
	panic("Web3 auth doesn't use OAuth flow")
}

func (p *Web3Provider) GetOAuthToken(code string) (*oauth2.Token, error) {
	panic("GetOAuthToken not implemented for Web3")
}

func (p *Web3Provider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	panic("GetUserData not implemented for Web3")
}

// VerifySignedMessage verifies a signed Web3 message based on the blockchain
func (p *Web3Provider) VerifySignedMessage(db *storage.Connection, params *Web3GrantParams) (*UserProvidedData, error) {   
	var err error
	
	parsedMessage, err := siws.ParseSIWSMessage(params.Message)

	if err != nil {
		return nil, siws.ErrorMalformedMessage
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
		case BlockchainSolana:
			err = p.verifySolanaSignature(params.Signature, params.Message, parsedMessage)
		default:
			return nil, httpError(http.StatusNotImplemented, "signature verification not implemented for %s", network)
	}

	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// Construct the provider_id as network:chain:address to make it unique
	// use concat
	providerId := (network[0] + ":" + network[1] + ":" + parsedMessage.Address)

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

