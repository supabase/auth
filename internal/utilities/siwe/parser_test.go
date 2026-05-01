package siwe

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseMessage(t *testing.T) {
	negativeExamples := []struct {
		example string
		error   error
	}{
		{
			example: "",
			error:   ErrMessageTooShort,
		},
		{
			example: "\n\n\n\n",
			error:   ErrMessageTooShort,
		},
		{
			example: "domain.com whatever\n\n\n\n\n\n",
			error:   ErrInvalidHeader,
		},
		{
			example: "******* wants you to sign in with your Ethereum account:\n\n\n\n\n\n",
			error:   ErrInvalidDomain,
		},
		{
			example: "domain.com wants you to sign in with your Ethereum account:\n***************************************\n\n\n\n\n",
			error:   ErrInvalidAddress,
		},
		{
			example: "domain.com wants you to sign in with your Ethereum account:\n0x742d35Cc6635C0532925a3b8D53d6e8b3f56ddF1\nURI: https://google.com\n\n\n",
			error:   ErrThirdLineNotEmpty,
		},
		{
			example: "domain.com wants you to sign in with your Ethereum account:\n0x742d35Cc6635C0532925a3b8D53d6e8b3f56ddF1\n\nStatement\n\nNot Parsable\n",
			error:   errUnparsableLine(5),
		},
		{
			example: "domain.com wants you to sign in with your Ethereum account:\n0x742d35Cc6635C0532925a3b8D53d6e8b3f56ddF1\n\nStatement\n\nVersion: 1\nURI: ***\nIssued At: 2025-01-01T00:00:00Z",
			error:   ErrInvalidURI,
		},
		{
			example: "domain.com wants you to sign in with your Ethereum account:\n0x742d35Cc6635C0532925a3b8D53d6e8b3f56ddF1\n\nStatement\n\nVersion: 1\nURI: https://google.com\nIssued At: not-a-timestamp",
			error:   ErrInvalidIssuedAt,
		},
		{
			example: "domain.com wants you to sign in with your Ethereum account:\n0x742d35Cc6635C0532925a3b8D53d6e8b3f56ddF1\n\nStatement\n\nVersion: 1\nURI: https://google.com\nIssued At: 2025-01-01T00:00:00Z\nExpiration Time: not-a-timestamp",
			error:   ErrInvalidExpirationTime,
		},
		{
			example: "domain.com wants you to sign in with your Ethereum account:\n0x742d35Cc6635C0532925a3b8D53d6e8b3f56ddF1\n\nStatement\n\nVersion: 1\nURI: https://google.com\nIssued At: 2025-01-01T00:00:00Z\nNot Before: not-a-timestamp",
			error:   ErrInvalidNotBefore,
		},
		{
			example: "domain.com wants you to sign in with your Ethereum account:\n0x742d35Cc6635C0532925a3b8D53d6e8b3f56ddF1\n\nStatement\n\nVersion: 2\nIssued At: 2025-01-01T00:00:00Z\nURI: https://google.com\n",
			error:   errUnsupportedVersion("2"),
		},
		{
			example: "domain.com wants you to sign in with your Ethereum account:\n0x742d35Cc6635C0532925a3b8D53d6e8b3f56ddF1\n\nStatement\n\nVersion: 1\nIssued At: 2025-01-01T00:00:00Z\n\n",
			error:   ErrMissingURI,
		},
		{
			example: "domain.com wants you to sign in with your Ethereum account:\n0x742d35Cc6635C0532925a3b8D53d6e8b3f56ddF1\n\nStatement\n\nVersion: 1\nURI: https://domain.com\nResources:\n- https://google.com\n",
			error:   ErrMissingIssuedAt,
		},
		{
			example: "domain.com wants you to sign in with your Ethereum account:\n0x742d35Cc6635C0532925a3b8D53d6e8b3f56ddF1\n\nStatement\n\nVersion: 1\nURI: https://domain.com\nIssued At: 2025-01-02T00:00:00Z\nExpiration Time: 2025-01-01T00:00:00Z\n",
			error:   ErrIssuedAfterExpiration,
		},
		{
			example: "domain.com wants you to sign in with your Ethereum account:\n0x742d35Cc6635C0532925a3b8D53d6e8b3f56ddF1\n\nStatement\n\nVersion: 1\nURI: https://domain.com\nIssued At: 2025-01-01T00:00:00Z\nExpiration Time: 2025-01-02T00:00:00Z\nNot Before: 2025-01-03T00:00:00Z\n",
			error:   ErrNotBeforeAfterExpiration,
		},
		{
			example: "domain.com wants you to sign in with your Ethereum account:\n0x742d35Cc6635C0532925a3b8D53d6e8b3f56ddF1\n\nStatement\n\nVersion: 1\nURI: https://domain.com\nIssued At: 2025-01-01T00:00:00Z\nResources:\n- https://google.com\n- ***\n",
			error:   errInvalidResource(1),
		},
		{
			example: "domain.com wants you to sign in with your Ethereum account:\n0x742d35Cc6635C0532925a3b8D53d6e8b3f56ddF1\n\nVersion: 1\nURI: https://domain.com\nIssued At: 2025-01-01T00:00:00Z\nChain ID: random:mainnet",
			error:   ErrInvalidChainID,
		},
	}

	for i, example := range negativeExamples {
		_, err := ParseMessage(example.example)

		t.Run(fmt.Sprintf("negative example %d", i), func(t *testing.T) {
			require.NotNil(t, err)
			require.Equal(t, example.error.Error(), err.Error())
		})
	}

	positiveExamples := []struct {
		message   string
		signature string
	}{
		{
			message:   "example.com wants you to sign in with your Ethereum account:\n0x196a28d05bA75C8dC35B0F6e71DD622D1aC82b7E\n\nSign in to Example App\n\nURI: https://example.com\nVersion: 1\nChain ID: 1\nNonce: 12345678\nIssued At: 2025-01-01T00:00:00.000Z",
			signature: "0xee337880f195524c156b8cc5f425ffcedb9d94638a91fa41ba72e26d93f04c9d1c7bca7020071c34ef7527ed6389ee24b59de79deab4e9e8251e6ca1e195a56a1b",
		},
		// Address: 0x196a28d05bA75C8dC35B0F6e71DD622D1aC82b7E
		{
			message:   "example.com wants you to sign in with your Ethereum account:\n0x196a28d05bA75C8dC35B0F6e71DD622D1aC82b7E\n\nURI: https://example.com\nVersion: 1\nChain ID: 1\nNonce: 12345678\nIssued At: 2025-01-01T00:00:00.000Z",
			signature: "0x0851224c203d08ced345bc99e66ac531eafbbb54eff94f7297b54ec19a0db7e879c4d246d45e0e13c9c2801db1f71f283c373b8c10cc0a91fe6418220a0aa5391b",
		},
	}

	for i, example := range positiveExamples {
		t.Run(fmt.Sprintf("positive example %d", i), func(t *testing.T) {
			parsed, err := ParseMessage(example.message)

			require.Nil(t, err)
			require.Equal(t, "example.com", parsed.Domain)
			// Address is normalized to lowercase regardless of input casing.
			// Ethereum addresses are protocol-level case-insensitive; EIP-55
			// mixed-case is a visual checksum, not a distinct identifier.
			require.Equal(t, "0x196a28d05ba75c8dc35b0f6e71dd622d1ac82b7e", parsed.Address)

			if i == 0 {
				require.Equal(t, "Sign in to Example App", *parsed.Statement)
			} else {
				require.Nil(t, parsed.Statement)
			}

			require.Equal(t, "2025-01-01 00:00:00 +0000 UTC", parsed.IssuedAt.String())
			require.Equal(t, "https://example.com", parsed.URI.String())
			require.Equal(t, "1", parsed.ChainID)
			require.Equal(t, "12345678", parsed.Nonce)
			// require.Equal(t, "abcdef", *parsed.RequestID)

			require.Equal(t, true, parsed.VerifySignature((example.signature)))
		})
	}
}

// TestParseMessageAddressNormalization asserts that ParseMessage lowercases
// the Ethereum address regardless of the input casing. Ethereum addresses
// are protocol-level case-insensitive (EIP-55 mixed-case is a visual checksum
// only), so storing them verbatim allowed the same wallet signing in with
// different casings to create duplicate auth.identities rows. See #2264.
func TestParseMessageAddressNormalization(t *testing.T) {
	const lowerAddress = "0x196a28d05ba75c8dc35b0f6e71dd622d1ac82b7e"
	const upperHexAddress = "0x196A28D05BA75C8DC35B0F6E71DD622D1AC82B7E"
	const checksumAddress = "0x196a28d05bA75C8dC35B0F6e71DD622D1aC82b7E"

	makeMessage := func(addr string) string {
		return "example.com wants you to sign in with your Ethereum account:\n" +
			addr +
			"\n\nURI: https://example.com\nVersion: 1\nChain ID: 1\nNonce: 12345678\nIssued At: 2025-01-01T00:00:00.000Z"
	}

	cases := []struct {
		name  string
		input string
	}{
		{name: "lowercase", input: lowerAddress},
		{name: "uppercase hex", input: upperHexAddress},
		{name: "EIP-55 checksum mixed case", input: checksumAddress},
	}

	parsedAddresses := make([]string, 0, len(cases))
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := ParseMessage(makeMessage(tc.input))
			require.Nil(t, err)
			require.Equal(t, lowerAddress, parsed.Address,
				"parser must lowercase Ethereum address so case-variant sign-ins do not create duplicate identities")
		})
		// Re-parse outside the subtest to collect for the equality assertion below.
		parsed, err := ParseMessage(makeMessage(tc.input))
		require.Nil(t, err)
		parsedAddresses = append(parsedAddresses, parsed.Address)
	}

	// All case variants of the same wallet must yield the exact same Address.
	for i := 1; i < len(parsedAddresses); i++ {
		require.Equal(t, parsedAddresses[0], parsedAddresses[i],
			"all case variants of the same Ethereum address must parse to the same value")
	}
}
