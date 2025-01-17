package siws

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// GenerateNonce creates a random 16-byte nonce, returning a hex-encoded string.
func GenerateNonce() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ValidateDomain checks if a domain is valid or not. This can be expanded with
// real domain validation logic. Here, we do a simple parse check.
func ValidateDomain(domain string) error {
	u, err := url.Parse("https://" + domain)
	if err != nil || u.Hostname() == "" {
		return errors.New("invalid domain")
	}
	return nil
}

// IsBase58PubKey checks if the input is a plausible base58 Solana public key.
// Typically Solana addresses are ~44 characters in base58. This is a naive check.
func IsBase58PubKey(address string) bool {
	address = strings.TrimSpace(address)
	if len(address) < 32 {
		return false
	}
	// Optionally, you could decode with base58 and check for 32 bytes.
	return true
}

// Add these functions to your existing helpers.go
func IsValidSolanaNetwork(network string) bool {
	validNetworks := map[string]bool{
		"mainnet": true,
		"devnet":  true,
		"testnet": true,
	}
	return validNetworks[strings.ToLower(network)]
}

// ValidateChainConfig ensures the Solana network configuration is valid
func ValidateChainConfig(chainStr string) error {
	if chainStr == "" {
		return errors.New("chain configuration cannot be empty")
	}

	network := strings.TrimSpace(strings.ToLower(chainStr))
	if !IsValidSolanaNetwork(network) {
		return fmt.Errorf("invalid Solana network: %s", network)
	}

	return nil
}

// Add these error types
var (
	ErrInvalidSolanaSignature = errors.New("invalid Solana signature")
	ErrInvalidSolanaAddress   = errors.New("invalid Solana address format")
	ErrExpiredMessage         = errors.New("SIWS message has expired")
)
