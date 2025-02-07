package siws

import (
	"fmt"
	"strings"
	"time"
)

// ConstructMessage creates the textual message to be signed, following
// an ABNF-like structure for "Sign in with Solana."
func ConstructMessage(msg SIWSMessage) string {
	var sb strings.Builder

	// 1) Domain request line
	sb.WriteString(fmt.Sprintf("%s wants you to sign in with your Solana account:\n", msg.Domain))

	// 2) Address
	sb.WriteString(fmt.Sprintf("%s\n", msg.Address))

	// 3) Optional statement
	if msg.Statement != "" {
		sb.WriteString(fmt.Sprintf("\n%s\n", msg.Statement))
	}

	// 4) Additional metadata (URI, Version, Nonce, IssuedAt)
	if msg.URI != "" {
		sb.WriteString(fmt.Sprintf("URI: %s\n", msg.URI))
	}
	if msg.Version != "" {
		sb.WriteString(fmt.Sprintf("Version: %s\n", msg.Version))
	}
	if msg.Nonce != "" {
		sb.WriteString(fmt.Sprintf("Nonce: %s\n", msg.Nonce))
	}
	if !msg.IssuedAt.IsZero() {
		sb.WriteString(fmt.Sprintf("Issued At: %s\n", msg.IssuedAt.UTC().Format(time.RFC3339)))
	}

	return sb.String()
}
