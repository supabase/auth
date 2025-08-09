package provider

import (
	"context"
	"errors"
	"strings"

	"github.com/supabase/auth/internal/conf"
	"golang.org/x/oauth2"
)

// Zitadel
type zitadelProvider struct {
	*oauth2.Config
	Host string
}

type zitadelUser struct {
	Name          string `json:"name"`
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

// NewZitadelProvider creates a Keycloak account provider.
func NewZitadelProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
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
		return nil, errors.New("unable to find URL for the Keycloak provider")
	}

	extURLlen := len(ext.URL)
	if ext.URL[extURLlen-1] == '/' {
		ext.URL = ext.URL[:extURLlen-1]
	}

	return &zitadelProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID[0],
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  ext.URL + "/oauth/v2/authorize",
				TokenURL: ext.URL + "/oauth/v2/token",
			},
			RedirectURL: ext.RedirectURI,
			Scopes:      oauthScopes,
		},
		Host: ext.URL,
	}, nil
}

func (g zitadelProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return g.Exchange(context.Background(), code)
}

func (g zitadelProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	var u zitadelUser

	if err := makeRequest(ctx, tok, g.Config, g.Host+"/oidc/v1/userinfo", &u); err != nil {
		return nil, err
	}

	data := &UserProvidedData{}
	if u.Email != "" {
		data.Emails = []Email{{
			Email:    u.Email,
			Verified: u.EmailVerified,
			Primary:  true,
		}}
	}

	data.Metadata = &Claims{
		Issuer:        g.Host,
		Subject:       u.Sub,
		Name:          u.Name,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,

		// To be deprecated
		FullName:   u.Name,
		ProviderId: u.Sub,
	}

	return data, nil

}
