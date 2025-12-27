package provider

import (
	"context"
	"strings"

	"github.com/supabase/auth/internal/conf"
	"golang.org/x/oauth2"
)

const (
	defaultLineAuthBase = "access.line.me"
	defaultLineAPIBase  = "api.line.me"
	IssuerLine          = "https://access.line.me"
)

type lineProvider struct {
	*oauth2.Config
	APIHost string
}

type lineUser struct {
	Subject       string `json:"sub"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

func NewLineProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.ValidateOAuth(); err != nil {
		return nil, err
	}

	authHost := chooseHost(ext.URL, defaultLineAuthBase)
	apiHost := chooseHost(ext.ApiURL, defaultLineAPIBase)

	oauthScopes := []string{
		"profile",
		"openid",
		"email",
	}

	if scopes != "" {
		oauthScopes = append(oauthScopes, strings.Split(scopes, ",")...)
	}

	return &lineProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID[0],
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authHost + "/oauth2/v2.1/authorize",
				TokenURL: apiHost + "/oauth2/v2.1/token",
			},
			RedirectURL: ext.RedirectURI,
			Scopes:      oauthScopes,
		},
		APIHost: apiHost,
	}, nil
}

func (p lineProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return p.Exchange(context.Background(), code)
}

func (p lineProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	var u lineUser
	if err := makeRequest(ctx, tok, p.Config, p.APIHost+"/oauth2/v2.1/userinfo", &u); err != nil {
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
		Issuer:            IssuerLine,
		Subject:           u.Subject,
		Name:              u.Name,
		PreferredUsername: u.Name,
		Picture:           u.Picture,
		Email:             u.Email,
		EmailVerified:     u.EmailVerified,

		AvatarURL:  u.Picture,
		FullName:   u.Name,
		ProviderId: u.Subject,
	}

	return data, nil
}
