package provider

import (
	"context"
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
}

var realIDTokens map[string]realIDToken = map[string]realIDToken{
	IssuerGoogle: realIDToken{
		AccessToken: "ya29.a0AWY7CkkHwdKOkkLSsAqEe8aGuw-_1RP-PTTUKO3WeX0cdkSY86h4W-xkajQgd6rXFjVHl44R69kDdFt0QZIQgdubGbwVNk5URkxegz9TkC1Tw055edvob7Y2dLo3VAzccs4CTTwT1qSnr1u1BIjheSEUbQguaCgYKASsSARESFQG1tDrpoU1f2gq-2cSRA0xjJf1sxA0163",
		IDToken:     "eyJhbGciOiJSUzI1NiIsImtpZCI6IjgyMjgzOGMxYzhiZjllZGNmMWY1MDUwNjYyZTU0YmNiMWFkYjViNWYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI5MTQ2NjY0MjA3NS03OWNwaWs4aWNxYzU4NjY5bjdtaXY5NjZsYmFwOTNhMi5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsImF1ZCI6IjkxNDY2NjQyMDc1LTc5Y3BpazhpY3FjNTg2NjluN21pdjk2NmxiYXA5M2EyLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwic3ViIjoiMTAzNzgzMTkwMTI2NDM5NzUxMjY5IiwiaGQiOiJzdXBhYmFzZS5pbyIsImVtYWlsIjoic3RvamFuQHN1cGFiYXNlLmlvIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF0X2hhc2giOiJGYU1La0Q5YlhJd2ZyY1JJWnVXZUV3IiwibmFtZSI6IlN0b2phbiBEaW1pdHJvdnNraSIsInBpY3R1cmUiOiJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS9BR05teXhhUWNrdUxnOXZxNGZyOF9KMkllc0daRl93TVNvQks3WEN2cXNRYz1zOTYtYyIsImdpdmVuX25hbWUiOiJTdG9qYW4iLCJmYW1pbHlfbmFtZSI6IkRpbWl0cm92c2tpIiwibG9jYWxlIjoiZW4tR0IiLCJpYXQiOjE2ODQ1Nzg1MzEsImV4cCI6MTY4NDU4MjEzMX0.Rwa8ebG0rUNowXsDLshqCEAEjkfxzurrhsEVm4DuJ9ncxBMyijw1-pwjLyqREaDnZbr8GUn8Nlft2gzw7ImgR5750sxOFwDIKEOBFfYIGq3-1tJMvVLG3G9zIPkm7mOrPvAAc5nM8JB15hB4ep7Bt_YcTSPXebewFJo5oBC9XQ_WsnIsvvpwdIdiSIhYmSfuWK-IjfsUIsysuM93mUcDhu_jzMJfeCqda4CQbNRE_WzcHS4B12bLmfT1Ho4ZSl0M4dKkMH_lUbIhi6kgu8xsW8lPMYrsvzvtOJWwK4tF3gL1lD_5JOs8eTnemn956yiPfL3dfMj6Kp6w9yMndgVbOQ",
		Time:        time.Unix(1684578532, 0), // 1 sec after iat
	},
	//IssuerApple: realIDToken{},
}

func TestParseIDToken(t *testing.T) {
	// note that this test can fail if/when the issuers rotate their
	// signing keys (which happens rarely if ever)
	// then you should obtain new ID tokens and update this test
	for issuer, token := range realIDTokens {
		oidcProvider, err := oidc.NewProvider(context.Background(), issuer)
		require.NoError(t, err)

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
