package siws

import (
	"crypto/ed25519"
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
		return nil, ErrMessageTooShort
	}

	// Parse first line exactly
	header := lines[0]
	if !strings.HasSuffix(header, headerSuffix) {
		return nil, ErrInvalidHeader
	}

	domain := strings.TrimSpace(strings.TrimSuffix(header, headerSuffix))
	if !IsValidDomain(domain) {
		return nil, ErrInvalidDomain
	}

	address := strings.TrimSpace(lines[1])
	if !addressPattern.MatchString(address) {
		return nil, ErrInvalidAddress
	}

	msg := &SIWSMessage{
		Raw:     raw,
		Domain:  domain,
		Address: address,
	}

	if lines[2] != "" {
		return nil, ErrThirdLineNotEmpty
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
					return nil, errInvalidResource(len(msg.Resources))
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
			return nil, errUnparsableLine(i)
		}

		value = strings.TrimSpace(value)

		switch key {
		case "URI":
			uri, err := url.ParseRequestURI(value)
			if err != nil {
				return nil, ErrInvalidURI
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
					return nil, ErrInvalidIssuedAt
				}
			}
			msg.IssuedAt = ts

		case "Expiration Time":
			ts, err := time.Parse(time.RFC3339, value)
			if err != nil {
				ts, err = time.Parse(time.RFC3339Nano, value)
				if err != nil {
					return nil, ErrInvalidExpirationTime
				}
			}
			msg.ExpirationTime = ts

		case "Not Before":
			ts, err := time.Parse(time.RFC3339, value)
			if err != nil {
				ts, err = time.Parse(time.RFC3339Nano, value)
				if err != nil {
					return nil, ErrInvalidNotBefore
				}
			}
			msg.NotBefore = ts

		case "Request ID":
			msg.RequestID = value
		}
	}

	if msg.Version != "1" {
		return nil, errUnsupportedVersion(msg.Version)
	}

	if msg.IssuedAt.IsZero() {
		return nil, ErrMissingIssuedAt
	}

	if msg.URI == nil {
		return nil, ErrMissingURI
	}

	if msg.ChainID != "" && !IsValidSolanaNetwork(msg.ChainID) {
		return nil, ErrInvalidChainID
	}

	if !msg.IssuedAt.IsZero() && !msg.ExpirationTime.IsZero() {
		if msg.IssuedAt.After(msg.ExpirationTime) {
			return nil, ErrIssuedAfterExpiration
		}
	}

	if !msg.NotBefore.IsZero() && !msg.ExpirationTime.IsZero() {
		if msg.NotBefore.After(msg.ExpirationTime) {
			return nil, ErrNotBeforeAfterExpiration
		}
	}

	return msg, nil
}

func (m *SIWSMessage) VerifySignature(signature []byte) bool {
	pubKey := base58.Decode(m.Address)

	return ed25519.Verify(pubKey, []byte(m.Raw), signature)
}
