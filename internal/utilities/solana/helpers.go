package siws

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/btcsuite/btcutil/base58"
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
func IsValidDomain(domain string) bool {
	// Regular expression to validate domain name
	regex := `^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`
	match, _ := regexp.MatchString(regex, domain)
	return match
}

// IsBase58PubKey checks if the input is a plausible base58 Solana public key.
func IsBase58PubKey(address string) bool {
	address = strings.TrimSpace(address)

	// Basic length check before trying to decode
	if len(address) == 0 {
		return false
	}

	decoded := base58.Decode(address)
	return len(decoded) == ed25519.PublicKeySize // ed25519.PublicKeySize is 32
}

// Add these functions to your existing helpers.go
func IsValidSolanaNetwork(network string) bool {
	switch network {
	case "mainnet", "devnet", "testnet":
		return true
	default:
		return false
	}
}

// ValidateChainConfig ensures the Solana network configuration is valid
func ValidateChainConfig(chainStr string) error {
	if chainStr == "" {
		return errors.New("siws: chain configuration cannot be empty")
	}

	network := strings.TrimSpace(strings.ToLower(chainStr))
	if !IsValidSolanaNetwork(network) {
		return fmt.Errorf("invalid Solana network: %s", network)
	}

	return nil
}

type SIWSError struct {
	Message    string
	StatusCode int
}

func (e *SIWSError) Error() string {
	return e.Message
}

func NewSIWSError(message string, statusCode int) *SIWSError {
	return &SIWSError{
		Message:    fmt.Sprintf("siws: %s", message),
		StatusCode: statusCode,
	}
}