package siws

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/btcsuite/btcutil/base58"
)

// SIWSMessage is the final structured form of a parsed SIWS message.
type SIWSMessage struct {
	Raw string

	Domain         string
	Address        string
	Statement      string
	URI            *url.URL
	Version        string
	Nonce          string
	IssuedAt       time.Time
	ChainID        string
	NotBefore      time.Time
	RequestID      string
	ExpirationTime time.Time
	Resources      []*url.URL
}

const headerSuffix = " wants you to sign in with your Solana account:"

var addressPattern = regexp.MustCompile("^[a-zA-Z0-9]{32,44}$")

func ParseMessage(raw string) (*SIWSMessage, error) {
	lines := strings.Split(raw, "\n")
	if len(lines) < 6 {
		return nil, errors.New("siws: message needs at least 6 lines")
	}

	// Parse first line exactly
	header := lines[0]
	if !strings.HasSuffix(header, headerSuffix) {
		return nil, fmt.Errorf("siws: message first line does not end in %q", headerSuffix)
	}

	domain := strings.TrimSpace(strings.TrimSuffix(header, headerSuffix))
	if !IsValidDomain(domain) {
		return nil, errors.New("siws: domain in first line of message is not valid")
	}

	address := strings.TrimSpace(lines[1])
	if !addressPattern.MatchString(address) {
		return nil, errors.New("siws: wallet address is not in base58 format")
	}

	msg := &SIWSMessage{
		Raw:     raw,
		Domain:  domain,
		Address: address,
	}

	if lines[2] != "" {
		return nil, errors.New("siws: third line must be empty")
	}

	startIndex := 3
	if lines[3] != "" && lines[4] == "" {
		msg.Statement = lines[3]
		startIndex = 5
	}

	inResources := false
	for i := startIndex; i < len(lines); i += 1 {
		line := strings.TrimSpace(lines[i])

		if inResources {
			if strings.HasPrefix(line, "- ") {
				resource := strings.TrimSpace(strings.TrimPrefix(line, "- "))

				resourceURL, err := url.ParseRequestURI(resource)
				if err != nil {
					return nil, fmt.Errorf("siws: Resource at position %d has invalid URI", len(msg.Resources))
				}

				msg.Resources = append(msg.Resources, resourceURL)
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

		key, value, found := strings.Cut(line, ":")
		if !found {
			return nil, fmt.Errorf("siws: encountered unparsable line at index %d", i)
		}

		value = strings.TrimSpace(value)

		switch key {
		case "URI":
			uri, err := url.ParseRequestURI(value)
			if err != nil {
				return nil, errors.New("siws: URI is not valid")
			}

			msg.URI = uri

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
					return nil, errors.New("siws: Issued At is not a valid ISO8601 timestamp")
				}
			}
			msg.IssuedAt = ts

		case "Expiration Time":
			ts, err := time.Parse(time.RFC3339, value)
			if err != nil {
				ts, err = time.Parse(time.RFC3339Nano, value)
				if err != nil {
					return nil, errors.New("siws: Expiration Time is not a valid ISO8601 timestamp")
				}
			}
			msg.ExpirationTime = ts

		case "Not Before":
			ts, err := time.Parse(time.RFC3339, value)
			if err != nil {
				ts, err = time.Parse(time.RFC3339Nano, value)
				if err != nil {
					return nil, errors.New("siws: Not Before is not a valid ISO8601 timestamp")
				}
			}
			msg.NotBefore = ts

		case "Request ID":
			msg.RequestID = value
		}
	}

	if msg.Version != "1" {
		return nil, fmt.Errorf("siws: Version value is not supported, expected 1 got %q", msg.Version)
	}

	if msg.IssuedAt.IsZero() {
		return nil, errors.New("siws: Issued At is not specified")
	}

	if msg.URI == nil {
		return nil, errors.New("siws: URI is not specified")
	}

	if msg.ChainID != "" && !IsValidSolanaNetwork(msg.ChainID) {
		return nil, errors.New("siws: Chain ID is not valid")
	}

	if !msg.IssuedAt.IsZero() && !msg.ExpirationTime.IsZero() {
		if msg.IssuedAt.After(msg.ExpirationTime) {
			return nil, errors.New("siws: Issued At is after Expiration Time")
		}
	}

	if !msg.NotBefore.IsZero() && !msg.ExpirationTime.IsZero() {
		if msg.NotBefore.After(msg.ExpirationTime) {
			return nil, errors.New("siws: Not Before is after Expiration Time")
		}
	}

	return msg, nil
}

func (m *SIWSMessage) VerifySignature(signature []byte) bool {
	pubKey := base58.Decode(m.Address)

	return ed25519.Verify(pubKey, []byte(m.Raw), signature)
}
