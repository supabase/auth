package siwk

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
			example: "******* wants you to sign in with your Kaspa account:\n\n\n\n\n\n",
			error:   ErrInvalidDomain,
		},
		{
			example: "domain.com wants you to sign in with your Kaspa account:\n***************************************\n\n\n\n\n",
			error:   ErrInvalidAddress,
		},
		{
			example: "domain.com wants you to sign in with your Kaspa account:\nkaspa:qqk948c2dy6cp0vdg7fqx9xttc47q4qdazunhmfv8u24v77uvmxhycc2uj3yn\nURI: https://google.com\n\n\n",
			error:   ErrThirdLineNotEmpty,
		},
		{
			example: "domain.com wants you to sign in with your Kaspa account:\nkaspa:qqk948c2dy6cp0vdg7fqx9xttc47q4qdazunhmfv8u24v77uvmxhycc2uj3yn\n\nStatement\n\nNot Parsable\n",
			error:   errUnparsableLine(5),
		},
		{
			example: "domain.com wants you to sign in with your Kaspa account:\nkaspa:qqk948c2dy6cp0vdg7fqx9xttc47q4qdazunhmfv8u24v77uvmxhycc2uj3yn\n\nStatement\n\nVersion: 1\nURI: ***\nIssued At: 2025-01-01T00:00:00Z",
			error:   ErrInvalidURI,
		},
		{
			example: "domain.com wants you to sign in with your Kaspa account:\nkaspa:qqk948c2dy6cp0vdg7fqx9xttc47q4qdazunhmfv8u24v77uvmxhycc2uj3yn\n\nStatement\n\nVersion: 1\nURI: https://google.com\nIssued At: not-a-timestamp",
			error:   ErrInvalidIssuedAt,
		},
		{
			example: "domain.com wants you to sign in with your Kaspa account:\nkaspa:qqk948c2dy6cp0vdg7fqx9xttc47q4qdazunhmfv8u24v77uvmxhycc2uj3yn\n\nStatement\n\nVersion: 1\nURI: https://google.com\nIssued At: 2025-01-01T00:00:00Z\nExpiration Time: not-a-timestamp",
			error:   ErrInvalidExpirationTime,
		},
		{
			example: "domain.com wants you to sign in with your Kaspa account:\nkaspa:qqk948c2dy6cp0vdg7fqx9xttc47q4qdazunhmfv8u24v77uvmxhycc2uj3yn\n\nStatement\n\nVersion: 1\nURI: https://google.com\nIssued At: 2025-01-01T00:00:00Z\nNot Before: not-a-timestamp",
			error:   ErrInvalidNotBefore,
		},
		{
			example: "domain.com wants you to sign in with your Kaspa account:\nkaspa:qqk948c2dy6cp0vdg7fqx9xttc47q4qdazunhmfv8u24v77uvmxhycc2uj3yn\n\nStatement\n\nVersion: 2\nIssued At: 2025-01-01T00:00:00Z\nURI: https://google.com\n",
			error:   errUnsupportedVersion("2"),
		},
		{
			example: "domain.com wants you to sign in with your Kaspa account:\nkaspa:qqk948c2dy6cp0vdg7fqx9xttc47q4qdazunhmfv8u24v77uvmxhycc2uj3yn\n\nStatement\n\nVersion: 1\nIssued At: 2025-01-01T00:00:00Z\n\n",
			error:   ErrMissingURI,
		},
		{
			example: "domain.com wants you to sign in with your Kaspa account:\nkaspa:qqk948c2dy6cp0vdg7fqx9xttc47q4qdazunhmfv8u24v77uvmxhycc2uj3yn\n\nStatement\n\nVersion: 1\nURI: https://domain.com\nResources:\n- https://google.com\n",
			error:   ErrMissingIssuedAt,
		},
		{
			example: "domain.com wants you to sign in with your Kaspa account:\nkaspa:qqk948c2dy6cp0vdg7fqx9xttc47q4qdazunhmfv8u24v77uvmxhycc2uj3yn\n\nStatement\n\nVersion: 1\nURI: https://domain.com\nIssued At: 2025-01-02T00:00:00Z\nExpiration Time: 2025-01-01T00:00:00Z\n",
			error:   ErrIssuedAfterExpiration,
		},
		{
			example: "domain.com wants you to sign in with your Kaspa account:\nkaspa:qqk948c2dy6cp0vdg7fqx9xttc47q4qdazunhmfv8u24v77uvmxhycc2uj3yn\n\nStatement\n\nVersion: 1\nURI: https://domain.com\nIssued At: 2025-01-01T00:00:00Z\nExpiration Time: 2025-01-02T00:00:00Z\nNot Before: 2025-01-03T00:00:00Z\n",
			error:   ErrNotBeforeAfterExpiration,
		},
		{
			example: "domain.com wants you to sign in with your Kaspa account:\nkaspa:qqk948c2dy6cp0vdg7fqx9xttc47q4qdazunhmfv8u24v77uvmxhycc2uj3yn\n\nStatement\n\nVersion: 1\nURI: https://domain.com\nIssued At: 2025-01-01T00:00:00Z\nResources:\n- https://google.com\n- ***\n",
			error:   errInvalidResource(1),
		},
		{
			example: "domain.com wants you to sign in with your Kaspa account:\nkaspa:qqk948c2dy6cp0vdg7fqx9xttc47q4qdazunhmfv8u24v77uvmxhycc2uj3yn\n\nVersion: 1\nURI: https://domain.com\nIssued At: 2025-01-01T00:00:00Z\nNetwork ID: random:mainnet",
			error:   ErrInvalidNetworkID,
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
			message:   "example.com wants you to sign in with your Kaspa account:\nkaspa:qqk948c2dy6cp0vdg7fqx9xttc47q4qdazunhmfv8u24v77uvmxhycc2uj3yn\n\nSign in to Example App\n\nURI: https://example.com\nVersion: 1\nNetwork ID: kaspa_mainnet\nNonce: 12345678\nIssued At: 2025-11-03T10:55:43.367Z",
			signature: "a8dd1b0eed80071ed22bed2392aa0a819e5c9fa5f62090aa89ba3a4cde531ec1460648b2cc84a416b0363d851896c9187f8afbccb0a931ec6bc11e9cb8b61543",
		},
		{
			message:   "example.com wants you to sign in with your Kaspa account:\nkaspa:qqk948c2dy6cp0vdg7fqx9xttc47q4qdazunhmfv8u24v77uvmxhycc2uj3yn\n\nURI: https://example.com\nVersion: 1\nNetwork ID: kaspa_mainnet\nNonce: 12345678\nIssued At: 2025-11-03T10:55:43.367Z",
			signature: "598ad18b808c5d625427dd917f1abef10e5c672d958e7e003e21b50df2fc0d3cd20bf99fb2278ab5b5865fa35108e53ab39aa3af0598cd4f2299867f682b85ec",
		},
	}

	for i, example := range positiveExamples {
		t.Run(fmt.Sprintf("positive example %d", i), func(t *testing.T) {
			parsed, err := ParseMessage(example.message)

			require.Nil(t, err)
			require.Equal(t, "example.com", parsed.Domain)
			require.Equal(t, "kaspa:qqk948c2dy6cp0vdg7fqx9xttc47q4qdazunhmfv8u24v77uvmxhycc2uj3yn", parsed.Address)

			if i == 0 {
				require.Equal(t, "Sign in to Example App", *parsed.Statement)
			} else {
				require.Nil(t, parsed.Statement)
			}

			println(parsed.IssuedAt.String())
			require.Equal(t, "2025-11-03 10:55:43.367 +0000 UTC", parsed.IssuedAt.String())
			require.Equal(t, "https://example.com", parsed.URI.String())
			require.Equal(t, "kaspa_mainnet", parsed.NetworkID)
			require.Equal(t, "12345678", parsed.Nonce)
			// require.Equal(t, "abcdef", *parsed.RequestID)

			require.Equal(t, true, parsed.VerifySignature((example.signature)))
		})
	}
}
