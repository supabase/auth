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

func azureIDTokenVerifier(ctx context.Context, config *oidc.Config) *oidc.IDTokenVerifier {
	keyBytes, err := base64.RawURLEncoding.DecodeString("1djHqyNclRpJWtHCnkP5QWvDxozCTG_ZDnkEmudpcxjnYrVL4RVIwdNCBLAStg8Dob5OUyAlHcRFMCqGTW4HA6kHgIxyfiFsYCBDMHWd2-61N1cAS6S9SdXlWXkBQgU0Qj6q_yFYTRS7J-zI_jMLRQAlpowfDFM1vSTBIci7kqynV6pPOz4jMaDQevmSscEs-jz7e8YXAiiVpN588oBQ0jzQaTTx90WjgRP23mn8mPyabj8gcR3gLwKLsBUhlp1oZj7FopGp8z8LHuueJB_q_LOUa_gAozZ0lfoJxFimXgpgEK7GNVdMRsMH3mIl0A5oYN8f29RFwbG0rNO5ZQ1YWQ")
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
		IssuerAzureMicrosoft,
		&oidc.StaticKeySet{
			PublicKeys: []crypto.PublicKey{publicKey},
		},
		config,
	)
}

var realIDTokens map[string]realIDToken = map[string]realIDToken{
	IssuerGoogle: {
		AccessToken: "ya29.a0AWY7CklOn4TehiT4kA6osNP6e-pHErOY8X53T2oUe7Oqqwc3-uIJpoEgoZCUogewBuNWr-JFT2FK9s0E0oRSFtAfu0-uIDckBj5ca1pxnk0-zPkPZouqoIyl0AlIpQjIUEuyuQTYUay99kRajbHcFCR1VMbNcQaCgYKAQESARESFQG1tDrp1joUHupV5Rn8-nWDpKkmMw0165",
		IDToken:     "eyJhbGciOiJSUzI1NiIsImtpZCI6Ijg1YmE5MzEzZmQ3YTdkNGFmYTg0ODg0YWJjYzg0MDMwMDQzNjMxODAiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI5MTQ2NjY0MjA3NS03OWNwaWs4aWNxYzU4NjY5bjdtaXY5NjZsYmFwOTNhMi5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsImF1ZCI6IjkxNDY2NjQyMDc1LTc5Y3BpazhpY3FjNTg2NjluN21pdjk2NmxiYXA5M2EyLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwic3ViIjoiMTAzNzgzMTkwMTI2NDM5NzUxMjY5IiwiaGQiOiJzdXBhYmFzZS5pbyIsImVtYWlsIjoic3RvamFuQHN1cGFiYXNlLmlvIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF0X2hhc2giOiJlcGVWV244VmxWa28zd195Unk3UDZRIiwibmFtZSI6IlN0b2phbiBEaW1pdHJvdnNraSIsInBpY3R1cmUiOiJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS9BQWNIVHRka0dhWjVlcGtqT1dxSEF1UUV4N2cwRlBCeXJiQ2ZNUjVNTk5kYz1zOTYtYyIsImdpdmVuX25hbWUiOiJTdG9qYW4iLCJmYW1pbHlfbmFtZSI6IkRpbWl0cm92c2tpIiwibG9jYWxlIjoiZW4tR0IiLCJpYXQiOjE2ODY2NTk5MzIsImV4cCI6MTY4NjY2MzUzMn0.nKAN9BFSxvavXYfWX4fZHREYY_3O4uOFRFq1KU1NNrBOMq_CPpM8c8PV7ZhKQvGCjBthSjtxGWbcqT0ByA7RdpNW6kj5UpFxEPdhenZ-eO1FwiEVIC8uZpiX6J3Nr7fAqi1P0DVeB3Zr_GrtkS9MDhZNb3hE5NDkvjCulwP4gRBC-5Pn_aRJRESxYkr_naKiSSmVilkmNVjZO4orq6KuYlvWHKHZIRiUI1akt0gVr5GxsEpd_duzUU30yVSPiq8l6fgxvJn2hT0MHa77wo3hvlP0NyAoSE7Nh4tRSowB0Qq7_byDMUmNWfXh-Qqa2M6ywuJ-_3LTLNUJH-cwdm2tNQ",
		Time:        time.Unix(1686659933, 0), // 1 sec after iat
		Verifier:    googleIDTokenVerifier,
	},
	IssuerAzureMicrosoft: {
		AccessToken: "access-token",
		Time:        time.Unix(1697277774, 0), // 1 sec after iat
		IDToken:     "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlhvdVhMWVExVGlwNW9kWWFqaUN0RlZnVmFFcyJ9.eyJ2ZXIiOiIyLjAiLCJpc3MiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vOTE4ODA0MGQtNmM2Ny00YzViLWIxMTItMzZhMzA0YjY2ZGFkL3YyLjAiLCJzdWIiOiJBQUFBQUFBQUFBQUFBQUFBQUFBQUFCWkRuRDkxOTBfc2wxcTZwenZlRHZNIiwiYXVkIjoiYTBkOGY5NzItNTRhYy00YWJmLTkxNGMtNTIyMDE0YzQwMjJhIiwiZXhwIjoxNjk3MzY0NDczLCJpYXQiOjE2OTcyNzc3NzMsIm5iZiI6MTY5NzI3Nzc3MywiZW1haWwiOiJzZGltaXRyb3Zza2lAZ21haWwuY29tIiwidGlkIjoiOTE4ODA0MGQtNmM2Ny00YzViLWIxMTItMzZhMzA0YjY2ZGFkIiwieG1zX2Vkb3YiOiIxIiwiYWlvIjoiRHBQV3lZSnRJcUl5OHpyVjROIUlIdGtFa09BMDhPS29lZ1RkYmZQUEVPYmxtYk9ESFQ0cGJVcVI1cExraENyWWZ6bUgzb3A1RzN5RGp2M0tNZ0Rad29lQ1FjKmVueldyb21iQ3BuKkR6OEpQOGMxU3pEVG1TbGp4U3U3UnVLTXNZSjRvS1lDazFBSVcqUUNUTmlMWkpUKlN3WWZQcjZBTW9IejFEZ3pBZEFkbk9uWiFHNUNFeEtQalBxcHRuVmpUZlEkJCJ9.CskICxOaeqd4SkiPdWEHJKZVdhAdgzM5SN7K7FYi0dguQH1-v6XTetDIoEsBn0GZoozXjbG2GgkFcVhhBvNA0ZrDIr4KcjfnJ5-7rwX3AtxdQ3umrHRlGu3jlmbDOtWzPWNMLLRXfR1Mm3pHEUvlzqmk3Ffh4TuAmXID-fb-Xmfuuv1k0UsZ5mlr_3ybTPVZk-Lj0bqkR1L5Zzt4HjgfpchRryJ3Y24b4dDsSjg7mgE_5JivgjhtVef5OnqYhKUF1DTy2pFysFO_eRliK6qjouYeZnQOJnWHP1MgpySAOQ3sVcwvE4P9g7V3QouxByZPv-g99N1K4GwZrtdm46gtTQ",
		Verifier:    azureIDTokenVerifier,
	},
	IssuerVercelMarketplace: {
		AccessToken: "access-token",
		Time:        time.Unix(1744883141, 0), // 1 sec after iat
		IDToken:     "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Im1yay00MzAyZWMxYjY3MGY0OGE5OGFkNjFkYWRlNGEyM2JlNyJ9.eyJpc3MiOiJodHRwczovL21hcmtldHBsYWNlLnZlcmNlbC5jb20iLCJzdWIiOiJhY2NvdW50OmRjYzIyNjJkZTY1ZjRmZGU2NDcyNWRkOWNiYzRjY2RlZjUzZWExNTc0NTU3ODZmNjU0YTdjNjNiZTQ3ZTI2YTE6dXNlcjo3Zjc5YjcwMDdkZWZjNmRlODZkMGQwZTEwMjM0NTlmYTFjMDljYjlhMGM2YzExY2I1YmQyMzRlMWJjZDVjOTkyIiwiYXVkIjoib2FjXzVuYzJGOGk3c3VYc0tmSjVURzc2NVRkeSIsImluc3RhbGxhdGlvbl9pZCI6ImljZmdfQ3hsUjhuRW9HOVc3bFFvSnB4QklFZGR3IiwiYWNjb3VudF9pZCI6ImRjYzIyNjJkZTY1ZjRmZGU2NDcyNWRkOWNiYzRjY2RlZjUzZWExNTc0NTU3ODZmNjU0YTdjNjNiZTQ3ZTI2YTEiLCJ1c2VyX2lkIjoiN2Y3OWI3MDA3ZGVmYzZkZTg2ZDBkMGUxMDIzNDU5ZmExYzA5Y2I5YTBjNmMxMWNiNWJkMjM0ZTFiY2Q1Yzk5MiIsInVzZXJfcm9sZSI6IkFETUlOIiwidXNlcl9lbWFpbCI6ImthbWlsLm9nb3Jla0BnbWFpbC5jb20iLCJnbG9iYWxfdXNlcl9pZCI6IjhyNlptNzFid2V6Z3daMlo1UWVCQm1oOCIsInVzZXJfbmFtZSI6IkthbWlsIE9nw7NyZWsiLCJ1c2VyX2F2YXRhcl91cmwiOiJodHRwczovL3ZlcmNlbC5jb20vYXBpL3d3dy9hdmF0YXIvODRhNzc0OTRjZWUwNjdmZWQyMTZjYzM3ZjY1ZTI1M2Y3OGZhMjgzMSIsIm5iZiI6MTc0NDg4MzE0MCwiaWF0IjoxNzQ0ODgzMTQwLCJleHAiOjE3NDQ4ODY3NDB9.bQ1CrgM7uGDmZs-ioEov9iosE-AFCHvfypasi-wEDEVD2uEcD4xU2C7vIXSLl_DAyIQFxWc7saQOcztiIltgHV3H_mSIBL1J2WKb7IX2dYe3bmxM32YC__vf_IKDzBFU7UufNEQW4fYq0abiej7heA4K_mJjvW_qZD-Skjxv51QdbXmcIUISrsS2jJID2B5cU0euBUV5Sc3sr1gLSrVIGChKROzboKG6Y0rtYAkjywdOGemHVz2aHBzo4uFxF1FcFx0EWGFI1AfNnSV0tP-RSOobfDai6RlCxmExUH2lEJaVrYfk9Hv5qIvbqtgrMv2LtqAydRhXHYmbAJHILmlK8Q",
	},
}

func TestParseIDToken(t *testing.T) {
	defer func() {
		OverrideVerifiers = make(map[string]func(context.Context, *oidc.Config) *oidc.IDTokenVerifier)
		OverrideClock = nil
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

func TestAzureIDTokenClaimsIsEmailVerified(t *testing.T) {
	positiveExamples := []AzureIDTokenClaims{
		{
			Email:                              "test@example.com",
			XMicrosoftEmailDomainOwnerVerified: nil,
		},
		{
			Email:                              "test@example.com",
			XMicrosoftEmailDomainOwnerVerified: true,
		},
		{
			Email:                              "test@example.com",
			XMicrosoftEmailDomainOwnerVerified: "1",
		},
		{
			Email:                              "test@example.com",
			XMicrosoftEmailDomainOwnerVerified: "true",
		},
	}

	negativeExamples := []AzureIDTokenClaims{
		{
			Email:                              "",
			XMicrosoftEmailDomainOwnerVerified: true,
		},
		{
			Email:                              "test@example.com",
			XMicrosoftEmailDomainOwnerVerified: false,
		},
		{
			Email:                              "test@example.com",
			XMicrosoftEmailDomainOwnerVerified: "0",
		},
		{
			Email:                              "test@example.com",
			XMicrosoftEmailDomainOwnerVerified: "false",
		},
		{
			Email:                              "test@example.com",
			XMicrosoftEmailDomainOwnerVerified: float32(0),
		},
		{
			Email:                              "test@example.com",
			XMicrosoftEmailDomainOwnerVerified: float64(0),
		},
		{
			Email:                              "test@example.com",
			XMicrosoftEmailDomainOwnerVerified: int(0),
		},
		{
			Email:                              "test@example.com",
			XMicrosoftEmailDomainOwnerVerified: int32(0),
		},
		{
			Email:                              "test@example.com",
			XMicrosoftEmailDomainOwnerVerified: int64(0),
		},
	}

	for i, example := range positiveExamples {
		if !example.IsEmailVerified() {
			t.Errorf("positive example %v reports negative result", i)
		}
	}

	for i, example := range negativeExamples {
		if example.IsEmailVerified() {
			t.Errorf("negative example %v reports positive result", i)
		}
	}
}
