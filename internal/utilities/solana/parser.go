package siws

import (
	"fmt"
	"strings"
	"time"
)

func ParseSIWSMessage(raw string) (*SIWSMessage, error) {
	// First split the message into lines
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	if len(lines) < 2 {
		return nil, ErrorMalformedMessage
	}

	// Parse first line exactly
	header := lines[0]
	if !strings.HasSuffix(header, " wants you to sign in with your Solana account:") {
		return nil, ErrorMalformedMessage
	}
	domain := strings.TrimSuffix(header, " wants you to sign in with your Solana account:")

	msg := &SIWSMessage{
		Domain:  domain,
		Address: strings.TrimSpace(lines[1]),
	}

	// Look for statement (double newline section)
	inResources := false
	for i := 2; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])

		if inResources {
			if strings.HasPrefix(line, "- ") {
				resource := strings.TrimSpace(strings.TrimPrefix(line, "- "))
				msg.Resources = append(msg.Resources, resource)
				continue
			} else {
				inResources = false
			}
		}

		if line == "Resources:" {
			inResources = true
			continue
		}

		if line == "" {
			continue
		}

		parts := strings.SplitN(line, ": ", 2)
		if len(parts) != 2 {
			// If we see a line without ": ", it might be a statement
			if !strings.Contains(line, ":") {
				msg.Statement = line
				continue
			}
			continue
		}

		key, value := parts[0], strings.TrimSpace(parts[1])
		switch key {
		case "URI":
			msg.URI = value
		case "Version":
			msg.Version = value
		case "Chain ID":
			msg.ChainID = value
		case "Nonce":
			msg.Nonce = value
		case "Issued At":
			ts, err := time.Parse(time.RFC3339, value)
			if err != nil {
				ts, err = time.Parse(time.RFC3339Nano, value)
				if err != nil {
					return nil, ErrInvalidIssuedAtFormat
				}
			}
			msg.IssuedAt = ts
		case "Expiration Time":
			ts, err := time.Parse(time.RFC3339, value)
			if err != nil {
				ts, err = time.Parse(time.RFC3339Nano, value)
				if err != nil {
					return nil, ErrInvalidExpirationTimeFormat
				}
			}
			msg.ExpirationTime = ts
		case "Not Before":
			ts, err := time.Parse(time.RFC3339, value)
			if err != nil {
				ts, err = time.Parse(time.RFC3339Nano, value)
				if err != nil {
					return nil, ErrInvalidNotBeforeFormat
				}
			}
			msg.NotBefore = ts
		case "Request ID":
			msg.RequestID = value
		case "Domain":
			// Debug prints
			fmt.Printf("Header domain: '%s'\n", msg.Domain)
			fmt.Printf("Field domain: '%s'\n", value)
			if value != msg.Domain {
				return nil, ErrMessageDomainMismatch
			}
		}
	}

	return msg, nil
}
