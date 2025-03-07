package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/url"
	"strconv"
	"strings"

	"crypto/ed25519"
	"time"

	"golang.org/x/crypto/hkdf"

	"github.com/btcsuite/btcutil/base58"
	siws "github.com/supabase/auth/internal/utilities/solana"
)

// GenerateOtp generates a random n digit otp
func GenerateOtp(digits int) string {
	upper := math.Pow10(digits)
	val := must(rand.Int(rand.Reader, big.NewInt(int64(upper))))

	// adds a variable zero-padding to the left to ensure otp is uniformly random
	expr := "%0" + strconv.Itoa(digits) + "v"
	otp := fmt.Sprintf(expr, val.String())

	return otp
}
func GenerateTokenHash(emailOrPhone, otp string) string {
	return fmt.Sprintf("%x", sha256.Sum224([]byte(emailOrPhone+otp)))
}

// Generated a random secure integer from [0, max[
func secureRandomInt(max int) int {
	randomInt := must(rand.Int(rand.Reader, big.NewInt(int64(max))))
	return int(randomInt.Int64())
}

type EncryptedString struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"alg"`
	Data      []byte `json:"data"`
	Nonce     []byte `json:"nonce,omitempty"`
}

func (es *EncryptedString) IsValid() bool {
	return es.KeyID != "" && len(es.Data) > 0 && len(es.Nonce) > 0 && es.Algorithm == "aes-gcm-hkdf"
}

// ShouldReEncrypt tells you if the value encrypted needs to be encrypted again with a newer key.
func (es *EncryptedString) ShouldReEncrypt(encryptionKeyID string) bool {
	return es.KeyID != encryptionKeyID
}

func (es *EncryptedString) Decrypt(id string, decryptionKeys map[string]string) ([]byte, error) {
	decryptionKey := decryptionKeys[es.KeyID]

	if decryptionKey == "" {
		return nil, fmt.Errorf("crypto: decryption key with name %q does not exist", es.KeyID)
	}

	key, err := deriveSymmetricKey(id, es.KeyID, decryptionKey)
	if err != nil {
		return nil, err
	}

	block := must(aes.NewCipher(key))
	cipher := must(cipher.NewGCM(block))

	decrypted, err := cipher.Open(nil, es.Nonce, es.Data, nil) // #nosec G407
	if err != nil {
		return nil, err
	}

	return decrypted, nil
}

func ParseEncryptedString(str string) *EncryptedString {
	if !strings.HasPrefix(str, "{") {
		return nil
	}

	var es EncryptedString

	if err := json.Unmarshal([]byte(str), &es); err != nil {
		return nil
	}

	if !es.IsValid() {
		return nil
	}

	return &es
}

func (es *EncryptedString) String() string {
	out := must(json.Marshal(es))

	return string(out)
}

func deriveSymmetricKey(id, keyID, keyBase64URL string) ([]byte, error) {
	hkdfKey, err := base64.RawURLEncoding.DecodeString(keyBase64URL)
	if err != nil {
		return nil, err
	}

	if len(hkdfKey) != 256/8 {
		return nil, fmt.Errorf("crypto: key with ID %q is not 256 bits", keyID)
	}

	// Since we use AES-GCM here, the same symmetric key *must not be used
	// more than* 2^32 times. But, that's not that much. Suppose a system
	// with 100 million users, then a user can only change their password
	// 42 times. To prevent this, the actual symmetric key is derived by
	// using HKDF using the encryption key and the "ID" of the object
	// containing the encryption string. Ideally this ID is a UUID.  This
	// has the added benefit that the encrypted string is bound to that
	// specific object, and can't accidentally be "moved" to other objects
	// without changing their ID to the original one.

	keyReader := hkdf.New(sha256.New, hkdfKey, nil, []byte(id))
	key := make([]byte, 256/8)

	must(io.ReadFull(keyReader, key))

	return key, nil
}

func NewEncryptedString(id string, data []byte, keyID string, keyBase64URL string) (*EncryptedString, error) {
	key, err := deriveSymmetricKey(id, keyID, keyBase64URL)
	if err != nil {
		return nil, err
	}

	block := must(aes.NewCipher(key))
	cipher := must(cipher.NewGCM(block))

	es := EncryptedString{
		KeyID:     keyID,
		Algorithm: "aes-gcm-hkdf",
		Nonce:     make([]byte, 12),
	}

	must(io.ReadFull(rand.Reader, es.Nonce))
	es.Data = cipher.Seal(nil, es.Nonce, data, nil) // #nosec G407

	return &es, nil
}

func VerifySIWS(
	rawMessage string,
	signature []byte,
	msg *siws.SIWSMessage,
	params siws.SIWSVerificationParams,
) error {
	var errors []error

	// Basic input validation
	if rawMessage == "" {
		errors = append(errors, siws.ErrEmptyRawMessage)
	}
	if len(signature) == 0 {
		errors = append(errors, siws.ErrEmptySignature)
	}
	if msg == nil {
		return siws.ErrNilMessage
	}

	// Domain validation
	if params.ExpectedDomain == "" {
		errors = append(errors, siws.ErrMissingDomain)
	}
	if !siws.IsValidDomain(msg.Domain) {
		errors = append(errors, siws.ErrInvalidDomainFormat)
	}
	if msg.Domain != params.ExpectedDomain {
		errors = append(errors, siws.ErrDomainMismatch)
	}

	// Address/Public Key validation
	pubKey := base58.Decode(msg.Address)
	validPubKey := siws.IsBase58PubKey(pubKey)
	if !validPubKey {
		errors = append(errors, siws.ErrInvalidPubKeySize)
	}

	// Version validation
	if msg.Version != "1" {
		errors = append(errors, siws.ErrInvalidVersion)
	}

	// Chain ID validation
	if msg.ChainID != "" && !siws.IsValidSolanaNetwork(msg.ChainID) {
		errors = append(errors, siws.ErrInvalidChainID)
	}

	// URI validation
	if msg.URI != "" {
		if _, err := url.Parse(msg.URI); err != nil {
			errors = append(errors, siws.ErrInvalidURI)
		}
	}

	// Resources validation
	for _, resource := range msg.Resources {
		if _, err := url.Parse(resource); err != nil {
			errors = append(errors, siws.ErrInvalidResourceURI)
		}
	}

	// Signature verification - only try if we have a valid public key
	if validPubKey && len(rawMessage) > 0 && len(signature) > 0 {
		if !ed25519.Verify(pubKey, []byte(rawMessage), signature) {
			errors = append(errors, siws.ErrSignatureVerification)
		}
	}

	// Time validations
	now := time.Now().UTC()

	if !msg.IssuedAt.IsZero() {
		if now.Before(msg.IssuedAt) {
			errors = append(errors, siws.ErrFutureMessage)
		}

		if params.CheckTime && params.TimeDuration > 0 {
			expiry := msg.IssuedAt.Add(params.TimeDuration)
			if now.After(expiry) {
				errors = append(errors, siws.ErrMessageExpired)
			}
		}
	}

	if !msg.NotBefore.IsZero() && now.Before(msg.NotBefore) {
		errors = append(errors, siws.ErrNotYetValid)
	}

	if !msg.ExpirationTime.IsZero() && now.After(msg.ExpirationTime) {
		errors = append(errors, siws.ErrMessageExpired)
	}

	// Return all validation errors as one error if any exist
	if len(errors) > 0 {
		if len(errors) == 1 {
			return errors[0] // Return single error directly to preserve its type
		}

		// Create error message with all errors
		var errMsgs []string
		for _, err := range errors {
			errMsgs = append(errMsgs, err.Error())
		}

		// Wrap the first error to maintain error type for errors.Is checks
		return fmt.Errorf("SIWS verification failed with multiple errors: %s (primary error: %w)",
			strings.Join(errMsgs, "; "), errors[0])
	}

	return nil
}

// SecureAlphanumeric generates a secure random alphanumeric string using standard library
func SecureAlphanumeric(length int) string {
	if length < 8 {
		length = 8
	}

	// Calculate bytes needed for desired length
	// base32 encoding: 5 bytes -> 8 chars
	numBytes := (length*5 + 7) / 8

	b := make([]byte, numBytes)
	must(io.ReadFull(rand.Reader, b))

	// Use standard library's base32 without padding
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))[:length]
}
