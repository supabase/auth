package siws

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	btcbase58 "github.com/btcsuite/btcutil/base58"
)

func TestSIWSFlow(t *testing.T) {
	// 1) Generate Ed25519 key pair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}
	pubKeyBase58 := btcbase58.Encode(pubKey)

	// 2) Build the SIWS message text (as the user would see)
	//    - Typically you'd store the nonce in DB now
	issuedAt := time.Now().UTC().Truncate(time.Second)
	rawMessage := `example.com wants you to sign in with your Solana account:
` + pubKeyBase58 + `

This is a test statement

URI: https://example.com
Version: 1
Nonce: ABCDEF123456
Issued At: ` + issuedAt.Format(time.RFC3339)

	// 3) Parse the message (robust approach)
	msg, parseErr := ParseSIWSMessage(rawMessage)
	if parseErr != nil {
		t.Fatalf("failed to parse message: %v", parseErr)
	}

	// 4) Sign the raw message
	signature := ed25519.Sign(privKey, []byte(rawMessage))

	// 5) Verify
	params := SIWSVerificationParams{
		ExpectedDomain: "example.com",
		CheckTime:      true,
		TimeDuration:   5 * time.Minute,
	}

	if err := VerifySIWS(rawMessage, signature, msg, params); err != nil {
		t.Fatalf("verification failed: %v", err)
	}
}

func TestBadDomain(t *testing.T) {
	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
	pubKeyBase58 := btcbase58.Encode(pubKey)

	rawMessage := `wrong-domain.com wants you to sign in with your Solana account:
` + pubKeyBase58 + `

URI: https://example.com
Version: 1
Nonce: SOME_NONCE
Issued At: 2025-01-01T00:00:00Z`

	msg, _ := ParseSIWSMessage(rawMessage)
	signature := ed25519.Sign(privKey, []byte(rawMessage))

	params := SIWSVerificationParams{
		ExpectedDomain: "example.com",
		CheckTime:      false,
	}

	err := VerifySIWS(rawMessage, signature, msg, params)
	if err == nil {
		t.Error("expected domain mismatch error, got nil")
	}
}

func TestBadSignature(t *testing.T) {
	_, privKey1, _ := ed25519.GenerateKey(rand.Reader)
	pubKey2, _, _ := ed25519.GenerateKey(rand.Reader)
	pubKey2Base58 := btcbase58.Encode(pubKey2)

	rawMessage := `example.com wants you to sign in with your Solana account:
` + pubKey2Base58 + `

Statement

Version: 1
Nonce: AAA
Issued At: 2025-01-01T00:00:00Z`

	msg, _ := ParseSIWSMessage(rawMessage)
	// Sign with privKey1 but the message references a different public key (pubKey2).
	signature := ed25519.Sign(privKey1, []byte(rawMessage))

	params := SIWSVerificationParams{
		ExpectedDomain: "example.com",
		CheckTime:      false,
	}

	err := VerifySIWS(rawMessage, signature, msg, params)
	if err == nil {
		t.Error("expected signature verification to fail, got success")
	}
}
