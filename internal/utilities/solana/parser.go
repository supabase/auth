package siws

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var (
	// domainRegex matches the first line of a SIWS message containing the domain
	domainRegex = regexp.MustCompile(`^([^ ]+)\s+wants you to sign in with your Solana account:$`)
)

// Common errors
var (
	ErrMessageTooShort     = errors.New("siws: message is too short or improperly formatted")
	ErrInvalidDomainFormat = errors.New("siws: first line does not match expected format for domain request")
	ErrMissingAddress      = errors.New("siws: missing address line")
)

// ParseSIWSMessage parses a raw SIWS message into an SIWSMessage struct,
// performing robust checks to ensure correct formatting.
func ParseSIWSMessage(raw string) (*SIWSMessage, error) {
	lines := strings.Split(raw, "\n")

	// Remove empty lines at the end or accidental trailing newlines.
	// Some wallets or frameworks may add them.
	var cleaned []string
	for _, line := range lines {
		l := strings.TrimSpace(line)
		if l != "" {
			cleaned = append(cleaned, l)
		}
	}

	if len(cleaned) < 2 {
		return nil, ErrMessageTooShort
	}

	// 1) First line should match "<domain> wants you to sign in with your Solana account:"
	matches := domainRegex.FindStringSubmatch(cleaned[0])
	if matches == nil || len(matches) < 2 {
		return nil, ErrInvalidDomainFormat
	}
	domain := matches[1]

	// 2) Second line is the base58-encoded public key
	address := strings.TrimSpace(cleaned[1])
	if address == "" {
		return nil, ErrMissingAddress
	}

	// The third line might be blank or might be the statement. We can handle that carefully.
	statement := ""
	lineIndex := 2

	if lineIndex < len(cleaned) {
		// If the line is blank, skip it; otherwise, treat it as statement
		if strings.HasPrefix(cleaned[lineIndex], "URI:") ||
			strings.HasPrefix(cleaned[lineIndex], "Version:") ||
			strings.HasPrefix(cleaned[lineIndex], "Nonce:") ||
			strings.HasPrefix(cleaned[lineIndex], "Issued At:") {
			// No statement
		} else {
			// We assume this line is statement
			statement = cleaned[lineIndex]
			lineIndex++
		}
	}

	var uri, version, nonce string
	var issuedAt time.Time

	// 3) Parse optional lines in the form "URI: ...", "Version: ...", "Nonce: ...", "Issued At: ..."
	for lineIndex < len(cleaned) {
		line := cleaned[lineIndex]
		switch {
		case strings.HasPrefix(line, "URI: "):
			uri = strings.TrimSpace(strings.TrimPrefix(line, "URI:"))
		case strings.HasPrefix(line, "Version: "):
			version = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
		case strings.HasPrefix(line, "Nonce: "):
			nonce = strings.TrimSpace(strings.TrimPrefix(line, "Nonce:"))
		case strings.HasPrefix(line, "Issued At: "):
			tsString := strings.TrimSpace(strings.TrimPrefix(line, "Issued At:"))
			var err error
			issuedAt, err = time.Parse(time.RFC3339, tsString)
			if err != nil {
				return nil, fmt.Errorf("siws: failed to parse Issued At time: %w", err)
			}
		default:
			return nil, fmt.Errorf("siws: unrecognized line: %s", line)
		}
		lineIndex++
	}

	// Construct the final message struct
	msg := &SIWSMessage{
		Domain:    domain,
		Address:   address,
		Statement: statement,
		URI:       uri,
		Version:   version,
		Nonce:     nonce,
		IssuedAt:  issuedAt,
	}

	return msg, nil
}
