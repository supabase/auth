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
	"log"
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
    log.Printf("[DEBUG] Starting SIWS verification - Signature length: %d", len(signature))

    // 1) Basic input validation
    if rawMessage == "" {
        log.Printf("[ERROR] Empty raw message")
        return siws.ErrEmptyRawMessage
    }
    if len(signature) == 0 {
        log.Printf("[ERROR] Empty signature")
        return siws.ErrEmptySignature
    }
    if msg == nil {
        log.Printf("[ERROR] Nil message")
        return siws.ErrNilMessage
    }

    log.Printf("[DEBUG] Basic validation passed - Message length: %d", len(rawMessage))

    // 2) Domain validation
    log.Printf("[DEBUG] Validating domain - Expected: %s, Actual: %s", params.ExpectedDomain, msg.Domain)
    if params.ExpectedDomain == "" {
        log.Printf("[ERROR] Missing expected domain")
        return siws.ErrMissingDomain
    }
    if !siws.IsValidDomain(msg.Domain) {
        log.Printf("[ERROR] Invalid domain format: %s", msg.Domain)
        return siws.ErrInvalidDomainFormat
    }
    if msg.Domain != params.ExpectedDomain {
        log.Printf("[ERROR] Domain mismatch - Expected: %s, Got: %s", params.ExpectedDomain, msg.Domain)
        return siws.ErrDomainMismatch
    }

    // 3) Address/Public Key validation
    pubKey := base58.Decode(msg.Address)
    log.Printf("[DEBUG] Validating public key - Address: %s, Decoded length: %d", msg.Address, len(pubKey))
    if !siws.IsBase58PubKey(pubKey) {
        log.Printf("[ERROR] Invalid public key size: %d", len(pubKey))
        return siws.ErrInvalidPubKeySize
    }

    // 4) Version validation
    log.Printf("[DEBUG] Checking version: %s", msg.Version)
    if msg.Version != "1" {
        log.Printf("[ERROR] Invalid version: %s", msg.Version)
        return siws.ErrInvalidVersion
    }

    // 5) Chain ID validation
    if msg.ChainID != "" {
        log.Printf("[DEBUG] Validating chain ID: %s", msg.ChainID)
        if !siws.IsValidSolanaNetwork(msg.ChainID) {
            log.Printf("[ERROR] Invalid chain ID: %s", msg.ChainID)
            return siws.ErrInvalidChainID
        }
    }

    // 7) URI validation
    if msg.URI != "" {
        log.Printf("[DEBUG] Validating URI: %s", msg.URI)
        if _, err := url.Parse(msg.URI); err != nil {
            log.Printf("[ERROR] Invalid URI: %s - %v", msg.URI, err)
            return siws.ErrInvalidURI
        }
    }

    // Resources validation
    for _, resource := range msg.Resources {
        log.Printf("[DEBUG] Validating resource URI: %s", resource)
        if _, err := url.Parse(resource); err != nil {
            log.Printf("[ERROR] Invalid resource URI: %s - %v", resource, err)
            return siws.ErrInvalidResourceURI
        }
    }

    // 8) Signature verification
    log.Printf("[DEBUG] Verifying ed25519 signature")
	log.Printf("[DEBUG] Verification inputs - Message bytes: %v", []byte(rawMessage))
	log.Printf("[DEBUG] Verification inputs - Signature bytes: %v", signature)
    if !ed25519.Verify(pubKey, []byte(rawMessage), signature) {
        log.Printf("[ERROR] Signature verification failed")
        return siws.ErrSignatureVerification
    }

    // 9) Time validations
    now := time.Now().UTC()
    log.Printf("[DEBUG] Time validation - Current time: %s", now)

    if !msg.IssuedAt.IsZero() {
        log.Printf("[DEBUG] Checking issuedAt: %s", msg.IssuedAt)
        if now.Before(msg.IssuedAt) {
            log.Printf("[ERROR] Message from future - IssuedAt: %s", msg.IssuedAt)
            return siws.ErrFutureMessage
        }

        if params.CheckTime && params.TimeDuration > 0 {
            expiry := msg.IssuedAt.Add(params.TimeDuration)
            log.Printf("[DEBUG] Checking message expiry - Expiry: %s", expiry)
            if now.After(expiry) {
                log.Printf("[ERROR] Message expired - Expiry: %s", expiry)
                return siws.ErrMessageExpired
            }
        }
    }

    if !msg.NotBefore.IsZero() {
        log.Printf("[DEBUG] Checking notBefore: %s", msg.NotBefore)
        if now.Before(msg.NotBefore) {
            log.Printf("[ERROR] Message not yet valid - NotBefore: %s", msg.NotBefore)
            return siws.ErrNotYetValid
        }
    }

    if !msg.ExpirationTime.IsZero() {
        log.Printf("[DEBUG] Checking expirationTime: %s", msg.ExpirationTime)
        if now.After(msg.ExpirationTime) {
            log.Printf("[ERROR] Message expired - ExpirationTime: %s", msg.ExpirationTime)
            return siws.ErrMessageExpired
        }
    }

    log.Printf("[INFO] SIWS verification successful")
    return nil
}

// SecureAlphanumeric generates a secure random alphanumeric string using standard library
func SecureAlphanumeric(length int) string {
    if length < 8 {
        length = 8
    }
    
    // Calculate bytes needed for desired length
    // base32 encoding: 5 bytes -> 8 chars
    numBytes := (length * 5 + 7) / 8
    
    b := make([]byte, numBytes)
    must(io.ReadFull(rand.Reader, b))
    
    // Use standard library's base32 without padding
    return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))[:length]
}

