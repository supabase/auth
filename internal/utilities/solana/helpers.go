package siws

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

var (
    // Input validation errors
    ErrEmptyRawMessage    = NewSIWSError("empty raw message", http.StatusBadRequest)
    ErrEmptySignature     = NewSIWSError("empty signature", http.StatusBadRequest)
    ErrNilMessage         = NewSIWSError("nil message", http.StatusBadRequest)
    
    // Domain errors
    ErrMissingDomain      = NewSIWSError("expected domain is not specified", http.StatusInternalServerError)
    ErrDomainMismatch     = NewSIWSError("domain mismatch", http.StatusForbidden)
    
    // Address errors
    ErrAddressLength      = NewSIWSError("address length invalid", http.StatusBadRequest)
    ErrAddressCharacter   = NewSIWSError("invalid address character", http.StatusBadRequest)
    ErrInvalidPubKeySize  = NewSIWSError("invalid public key size", http.StatusBadRequest)
    
    // Version errors
    ErrInvalidVersion     = NewSIWSError("invalid version", http.StatusBadRequest)
    
    // Chain ID errors
    ErrInvalidChainID     = NewSIWSError("invalid chain ID", http.StatusBadRequest)
    
    // Nonce errors
    ErrNonceTooShort      = NewSIWSError("nonce too short", http.StatusBadRequest)
    ErrInvalidNonceChar   = NewSIWSError("invalid nonce character", http.StatusBadRequest)
    
    // URI errors
    ErrInvalidURI         = NewSIWSError("invalid URI", http.StatusBadRequest)
    ErrInvalidResourceURI = NewSIWSError("invalid resource URI", http.StatusBadRequest)
    
    // Signature errors
    ErrSignatureVerification = NewSIWSError("signature verification failed", http.StatusUnauthorized)
    
    // Time validation errors
    ErrFutureMessage      = NewSIWSError("message is issued in the future", http.StatusBadRequest)
    ErrMessageExpired     = NewSIWSError("message is expired", http.StatusUnauthorized)
    ErrNotYetValid        = NewSIWSError("message not yet valid", http.StatusUnauthorized)
	ErrorCodeInvalidNonce = NewSIWSError("invalid nonce", http.StatusBadRequest)
	ErrorCodeInvalidSignature = NewSIWSError("invalid signature", http.StatusBadRequest)
	ErrorMalformedMessage = NewSIWSError("malformed message", http.StatusBadRequest)
	ErrInvalidDomainFormat = NewSIWSError("invalid domain format", http.StatusBadRequest)
	ErrInvalidStatementFormat = NewSIWSError("invalid statement format", http.StatusBadRequest)
	ErrInvalidIssuedAtFormat = NewSIWSError("invalid issued at format", http.StatusBadRequest)
	ErrInvalidExpirationTimeFormat = NewSIWSError("invalid expiration time format", http.StatusBadRequest)
	ErrInvalidNotBeforeFormat = NewSIWSError("invalid not before format", http.StatusBadRequest)
	ErrUnrecognizedLine = NewSIWSError("unrecognized line", http.StatusBadRequest)
	
	
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
func IsBase58PubKey(address []byte) bool {
		return len(address) == ed25519.PublicKeySize // ed25519.PublicKeySize is 32
}

// Add these functions to your existing helpers.go
func IsValidSolanaNetwork(network string) bool {
    // Handle optional "solana:" prefix
    network = strings.TrimPrefix(network, "solana:")
    
    switch network {
    case "mainnet", "devnet", "testnet", "localnet":
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