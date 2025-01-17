package siws

import (
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/btcsuite/btcutil/base58"
)

// VerifySIWS fully verifies:
//   - The domain in msg matches expected domain
//   - The ed25519 signature matches the parsed SIWS message text
//   - The base58-encoded public key is valid
//   - The message is within the allowed time window (if requested)
func VerifySIWS(
	rawMessage string, // the original textual message
	signature []byte, // signature returned by the client
	msg *SIWSMessage, // the parsed SIWS message (from ParseSIWSMessage)
	params SIWSVerificationParams,
) error {
	// 1) Domain check
	if params.ExpectedDomain == "" {
		return errors.New("expected domain is not specified")
	}
	if msg.Domain != params.ExpectedDomain {
		return errors.New("domain mismatch")
	}

	// 2) Base58 decode -> ed25519.PublicKey
	pubKey := base58.Decode(msg.Address)
	if len(pubKey) != ed25519.PublicKeySize {
		return errors.New("invalid base58 public key or wrong size (must be 32 bytes)")
	}

	// 3) Verify signature
	//    The message to verify must be exactly the raw text that was originally signed.
	if !ed25519.Verify(pubKey, []byte(rawMessage), signature) {
		return errors.New("signature verification failed")
	}

	// 4) Time check if requested
	if params.CheckTime && params.TimeDuration > 0 {
		if msg.IssuedAt.IsZero() {
			return errors.New("issuedAt not set, but time check requested")
		}
		now := time.Now().UTC()
		expiry := msg.IssuedAt.Add(params.TimeDuration)
		if now.Before(msg.IssuedAt) {
			return errors.New("message is issued in the future")
		}
		if now.After(expiry) {
			return errors.New("message is expired")
		}
	}

	return nil
}
