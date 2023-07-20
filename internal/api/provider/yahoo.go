package provider

import (
	"context"
	"errors"
	"strings"

	"github.com/supabase/gotrue/internal/conf"
	"golang.org/x/oauth2"
)

// Yahoo
type yahooProvider struct {
	*oauth2.Config
	Host string
}

type yahooUser struct {
	Name          string `json:"name"`
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

// NewYahooProvider creates a Yahoo account provider.
func NewYahooProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.ValidateOAuth(); err != nil {
		return nil, err
	}

	oauthScopes := []string{
		"profile",
		"email",
	}

	if scopes != "" {
		oauthScopes = append(oauthScopes, strings.Split(scopes, ",")...)
	}

	if ext.URL == "" {
		return nil, errors.New("unable to find URL for the Yahoo provider")
	}

	extURLlen := len(ext.URL)
	if ext.URL[extURLlen-1] == '/' {
		ext.URL = ext.URL[:extURLlen-1]
	}

	return &yahooProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID[0],
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  ext.URL + "/protocol/openid-connect/auth",
				TokenURL: ext.URL + "/protocol/openid-connect/token",
			},
			RedirectURL: ext.RedirectURI,
			Scopes:      oauthScopes,
		},
		Host: ext.URL,
	}, nil
}

func (g YahooProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return g.Exchange(context.Background(), code)
}

func (g YahooProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	var u YahooUser

	if err := makeRequest(ctx, tok, g.Config, g.Host+"/protocol/openid-connect/userinfo", &u); err != nil {
		return nil, err
	}

	if u.Email == "" {
		return nil, errors.New("unable to find email with Yahoo provider")
	}

	return &UserProvidedData{
		Metadata: &Claims{
			Issuer:        g.Host,
			Subject:       u.Sub,
			Name:          u.Name,
			Email:         u.Email,
			EmailVerified: u.EmailVerified,

			// To be deprecated
			FullName:   u.Name,
			ProviderId: u.Sub,
		},
		Emails: []Email{{
			Email:    u.Email,
			Verified: u.EmailVerified,
			Primary:  true,
		}},
	}, nil

}
