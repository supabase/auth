package siws

import (
	"time"
)

// SIWSMessage is the final structured form of a parsed SIWS message.
type SIWSMessage struct {
	Domain    string    // e.g. "example.com"
	Address   string    // base58-encoded Solana public key
	Statement string    // optional
	URI       string    // optional
	Version   string    // recommended (e.g. "1")
	Nonce     string    // random nonce
	IssuedAt  time.Time // "Issued At" timestamp
	// ExpirationTime is optional. If set, it should be checked against the current time.
	ExpirationTime time.Time
}

// SIWSVerificationParams holds parameters needed to verify an SIWS message.
type SIWSVerificationParams struct {
	// The domain we expect. Must match message.Domain.
	ExpectedDomain string

	// Whether or not to enforce time validity (IssuedAt <= now <= IssuedAt + TimeDuration).
	CheckTime    bool
	TimeDuration time.Duration
}
