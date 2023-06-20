package provider

import (
	"context"
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/require"
)

type realIDToken struct {
	AccessToken string
	IDToken     string
	Time        time.Time
	Email       string
	Verifier    func(context.Context, *oidc.Config) *oidc.IDTokenVerifier
}

func googleIDTokenVerifier(ctx context.Context, config *oidc.Config) *oidc.IDTokenVerifier {
	keyBytes, err := base64.RawURLEncoding.DecodeString("pP-rCe4jkKX6mq8yP1GcBZcxJzmxKWicHHor1S3Q49u6Oe-bQsk5NsK5mdR7Y7liGV9n0ikXSM42dYKQdxbhKA-7--fFon5isJoHr4fIwL2CCwVm5QWlK37q6PiH2_F1M0hRorHfkCb4nI56ZvfygvuOH4LIS82OzIgmsYbeEfwDRpeMSxWKwlpa3pX3GZ6jG7FgzJGBvmBkagpgsa2JZdyU4gEGMOkHdSzi5Ii-6RGfFLhhI1OMxC9P2JaU5yjMN2pikfFIq_dbpm75yNUGpWJNVywtrlNvvJfA74UMN_lVCAaSR0A03BUMg6ljB65gFllpKF224uWBA8tpjngwKQ")
	if err != nil {
		panic(err)
	}

	n := big.NewInt(0)
	n.SetBytes(keyBytes)

	publicKey := &rsa.PublicKey{
		N: n,
		E: 65537,
	}

	return oidc.NewVerifier(
		"https://accounts.google.com",
		&oidc.StaticKeySet{
			PublicKeys: []crypto.PublicKey{publicKey},
		},
		config,
	)
}

var realIDTokens map[string]realIDToken = map[string]realIDToken{
	IssuerGoogle: realIDToken{
		AccessToken: "ya29.a0AWY7CklOn4TehiT4kA6osNP6e-pHErOY8X53T2oUe7Oqqwc3-uIJpoEgoZCUogewBuNWr-JFT2FK9s0E0oRSFtAfu0-uIDckBj5ca1pxnk0-zPkPZouqoIyl0AlIpQjIUEuyuQTYUay99kRajbHcFCR1VMbNcQaCgYKAQESARESFQG1tDrp1joUHupV5Rn8-nWDpKkmMw0165",
		IDToken:     "eyJhbGciOiJSUzI1NiIsImtpZCI6Ijg1YmE5MzEzZmQ3YTdkNGFmYTg0ODg0YWJjYzg0MDMwMDQzNjMxODAiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI5MTQ2NjY0MjA3NS03OWNwaWs4aWNxYzU4NjY5bjdtaXY5NjZsYmFwOTNhMi5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsImF1ZCI6IjkxNDY2NjQyMDc1LTc5Y3BpazhpY3FjNTg2NjluN21pdjk2NmxiYXA5M2EyLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwic3ViIjoiMTAzNzgzMTkwMTI2NDM5NzUxMjY5IiwiaGQiOiJzdXBhYmFzZS5pbyIsImVtYWlsIjoic3RvamFuQHN1cGFiYXNlLmlvIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF0X2hhc2giOiJlcGVWV244VmxWa28zd195Unk3UDZRIiwibmFtZSI6IlN0b2phbiBEaW1pdHJvdnNraSIsInBpY3R1cmUiOiJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS9BQWNIVHRka0dhWjVlcGtqT1dxSEF1UUV4N2cwRlBCeXJiQ2ZNUjVNTk5kYz1zOTYtYyIsImdpdmVuX25hbWUiOiJTdG9qYW4iLCJmYW1pbHlfbmFtZSI6IkRpbWl0cm92c2tpIiwibG9jYWxlIjoiZW4tR0IiLCJpYXQiOjE2ODY2NTk5MzIsImV4cCI6MTY4NjY2MzUzMn0.nKAN9BFSxvavXYfWX4fZHREYY_3O4uOFRFq1KU1NNrBOMq_CPpM8c8PV7ZhKQvGCjBthSjtxGWbcqT0ByA7RdpNW6kj5UpFxEPdhenZ-eO1FwiEVIC8uZpiX6J3Nr7fAqi1P0DVeB3Zr_GrtkS9MDhZNb3hE5NDkvjCulwP4gRBC-5Pn_aRJRESxYkr_naKiSSmVilkmNVjZO4orq6KuYlvWHKHZIRiUI1akt0gVr5GxsEpd_duzUU30yVSPiq8l6fgxvJn2hT0MHa77wo3hvlP0NyAoSE7Nh4tRSowB0Qq7_byDMUmNWfXh-Qqa2M6ywuJ-_3LTLNUJH-cwdm2tNQ",
		Time:        time.Unix(1686659933, 0), // 1 sec after iat
		Verifier:    googleIDTokenVerifier,
	},
}

func TestParseIDToken(t *testing.T) {
	defer func() {
		OverrideVerifiers = make(map[string]func(context.Context, *oidc.Config) *oidc.IDTokenVerifier)
	}()

	// note that this test can fail if/when the issuers rotate their
	// signing keys (which happens rarely if ever)
	// then you should obtain new ID tokens and update this test
	for issuer, token := range realIDTokens {
		oidcProvider, err := oidc.NewProvider(context.Background(), issuer)
		require.NoError(t, err)

		OverrideVerifiers[oidcProvider.Endpoint().AuthURL] = token.Verifier

		_, user, err := ParseIDToken(context.Background(), oidcProvider, &oidc.Config{
			SkipClientIDCheck: true,
			Now: func() time.Time {
				return token.Time
			},
		}, token.IDToken, ParseIDTokenOptions{
			AccessToken: token.AccessToken,
		})
		require.NoError(t, err)

		require.NotEmpty(t, user.Emails[0].Email)
		require.Equal(t, user.Emails[0].Verified, true)
	}
}
