package siwk

import (
	"encoding/hex"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/kaspanet/go-secp256k1"
	"github.com/kaspanet/kaspad/util/bech32"
)

// SIWKMessage is the final structured form of a parsed SIWE message.
// REF: https://eips.ethereum.org/EIPS/eip-4361
type SIWKMessage struct {
	Raw string

	Domain         string
	Address        string
	Statement      *string
	URI            url.URL
	Version        string
	NetworkID      string
	Nonce          string
	IssuedAt       time.Time
	ExpirationTime *time.Time
	NotBefore      *time.Time
	RequestID      *string
	Resources      []*url.URL
}

const headerSuffix = " wants you to sign in with your Kaspa account:"

var addressPattern = regexp.MustCompile("^(kaspa|kaspatest|kaspadev|kaspasim):[a-zA-Z0-9]+$")

func ParseMessage(raw string) (*SIWKMessage, error) {
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

	msg := &SIWKMessage{
		Raw:     raw,
		Domain:  domain,
		Address: address,
	}

	if lines[2] != "" {
		return nil, ErrThirdLineNotEmpty
	}

	startIndex := 3
	if lines[3] != "" && lines[4] == "" {
		statement := lines[3]
		msg.Statement = &statement
		startIndex = 5
	}

	inResources := false
	for i := startIndex; i < len(lines); i++ {

		line := strings.TrimSpace(lines[i])

		if inResources {
			if after, ok := strings.CutPrefix(line, "- "); ok {
				resource := strings.TrimSpace(after)

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
			msg.URI = *uri

		case "Version":
			msg.Version = value

		case "Network ID":
			if value == "" || !isValidKaspaNetwork(value) {
				return nil, ErrInvalidNetworkID
			}
			msg.NetworkID = value

		case "Nonce":
			// this is supposed to be REQUIRED >8 chr alphanum but we'll leave it for now for gotrue's nonce impl
			msg.Nonce = value

		case "Issued At":
			ts, err := time.Parse(time.RFC3339, value)
			if err != nil {
				ts, err = time.Parse(time.RFC3339Nano, value)
				if err != nil {
					return nil, ErrInvalidIssuedAt
				}
			}
			if ts.IsZero() {
				return nil, ErrMissingIssuedAt
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
			msg.ExpirationTime = &ts

		case "Not Before":
			ts, err := time.Parse(time.RFC3339, value)
			if err != nil {
				ts, err = time.Parse(time.RFC3339Nano, value)
				if err != nil {
					return nil, ErrInvalidNotBefore
				}
			}

			msg.NotBefore = &ts

		case "Request ID":
			// This is supposed to be a pchar (RFC 3986) but generally we'll keep it as any str for now
			msg.RequestID = &value
		}
	}

	if msg.Version != "1" && msg.Version != "0" {
		return nil, errUnsupportedVersion(msg.Version)
	}

	if msg.IssuedAt.IsZero() {
		return nil, ErrMissingIssuedAt
	}

	if msg.URI.String() == "" {
		return nil, ErrMissingURI
	}

	if msg.ExpirationTime != nil && !msg.IssuedAt.IsZero() {
		if msg.IssuedAt.After(*msg.ExpirationTime) {
			return nil, ErrIssuedAfterExpiration
		}
	}

	if msg.NotBefore != nil && msg.ExpirationTime != nil {
		if msg.NotBefore.After(*msg.ExpirationTime) {
			return nil, ErrNotBeforeAfterExpiration
		}
	}

	return msg, nil
}

// VerifySignature validates that the signature was created by the private key
// corresponding to the address in the message. This performs ECDSA recovery
// which is computationally expensive, so it should be called only after
// ParseMessage has validated the message structure.
//
// The signature must be a 65-byte hex string in the format: 0x{R}{S}{V}
// where R and S are 32 bytes each and V is 1 byte.
//
// Returns true if the recovered address matches the message address (case-insensitive).
func (m *SIWKMessage) VerifySignature(signatureHex string) bool {
	sig, err := hexutil.Decode(signatureHex)
	if err != nil || len(sig) != 64 {
		panic("siwk: signature must be a 64-byte hex string")
	}

	// Create signature in [R || S || V] format
	signature := make([]byte, 64)
	copy(signature, sig)

	// Normalize V if needed
	// #nosec G602
	if signature[64] >= 27 {
		signature[64] -= 27 // #nosec G602
	}

	hash := accounts.TextHash([]byte(m.Raw))

	// Recover public key
	pubKey, err := crypto.Ecrecover(hash, signature)
	if err != nil {
		panic("siwk: failed to recover public key: " + err.Error())
	}

	// Convert to address
	recoveredAddr := common.BytesToAddress(crypto.Keccak256(pubKey[1:])[12:])

	return strings.EqualFold(recoveredAddr.Hex(), m.Address)
}

func (m *SIWKMessage) VerifySignatureSchnorr(signatureHex string) bool {
	sigBytes, err := hex.DecodeString(signatureHex)
	if err != nil {
		panic("siwk: invalid signature hex: " + err.Error())
	}

	if len(sigBytes) != 64 {
		panic("siwk: signature must be 64 bytes long")
	}

	_, pkBytes, version, err := bech32.Decode(m.Address)
	if err != nil {
		panic("siwk: invalid Kaspa address: " + err.Error())
	}

	if version != 0 && version != 1 {
		panic("siwk: unsupported Kaspa address version, expected 0 or 1, found:" + string(version))
	}

	if version == 0 && len(pkBytes) != 32 {
		panic("siwk: invalid schnorr public key length for version 0, expected 32 bytes, found:" + string(len(pkBytes)))
	}

	if version == 1 && len(pkBytes) != 33 {
		panic("siwk: invalid schnorr public key length for version 1, expected 33 bytes, found:" + string(len(pkBytes)))
	}

	var ok bool

	if version == 0 {
		// gt signature bytes from hex
		var signature secp256k1.SerializedSchnorrSignature

		_, err = hex.Decode(signature[:], []byte(signatureHex))
		if err != nil {
			panic("siwk: failed to decode signature hex: " + err.Error())
		}

		// Verify using Schnorr
		ok, err = VerifySchnorr([]byte(m.Raw), signature[:], pkBytes)
		if err != nil {
			panic("siwk: failed to verify schnorr signature: " + err.Error())
		}

		return ok
	}

	if version == 1 {
		ok, err = VerifyECDSA([]byte(m.Raw), sigBytes, pkBytes)

		if err != nil {
			panic("siwk: failed to verify ecdsa signature: " + err.Error())
		}

		return ok
	}

	return false
}
