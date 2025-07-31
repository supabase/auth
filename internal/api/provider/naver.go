package provider

import (
	"context"
	"strings"

	"github.com/supabase/auth/internal/conf"
	"golang.org/x/oauth2"
)

const (
	defaultNaverAuthBase = "nid.naver.com"
	defaultNaverAPIBase  = "openapi.naver.com"
	IssuerNaver          = "https://nid.naver.com"
)

type naverProvider struct {
	*oauth2.Config
	APIHost string
}

type naverUserResponse struct {
	Response struct {
		ID              string `json:"id"`
		Name            string `json:"name"`
		ProfileImageURL string `json:"profile_image"`
		Email           string `json:"email"`
	} `json:"response"`
}

func (p naverProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return p.Exchange(context.Background(), code)
}

func (p naverProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	var u naverUserResponse

	if err := makeRequest(ctx, tok, p.Config, p.APIHost+"/v1/nid/me", &u); err != nil {
		return nil, err
	}

	data := &UserProvidedData{}

	if u.Response.Email != "" {
		data.Emails = []Email{
			{
				Email:    u.Response.Email,
				Verified: true,
				Primary:  true,
			},
		}
	}

	data.Metadata = &Claims{
		Issuer:  p.APIHost,
		Subject: u.Response.ID,

		Name:              u.Response.Name,
		PreferredUsername: u.Response.Name,

		// To be deprecated
		AvatarURL:   u.Response.ProfileImageURL,
		FullName:    u.Response.Name,
		ProviderId:  u.Response.ID,
		UserNameKey: u.Response.Name,
	}
	return data, nil
}

func NewNaverProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.ValidateOAuth(); err != nil {
		return nil, err
	}

	authHost := chooseHost(ext.URL, defaultNaverAuthBase)
	apiHost := chooseHost(ext.URL, defaultNaverAPIBase)

	oauthScopes := []string{
		"openid",
	}

	if scopes != "" {
		oauthScopes = append(oauthScopes, strings.Split(scopes, ",")...)
	}

	return &naverProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID[0],
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthStyle: oauth2.AuthStyleInParams,
				AuthURL:   authHost + "/oauth2.0/authorize",
				TokenURL:  authHost + "/oauth2.0/token",
			},
			RedirectURL: ext.RedirectURI,
			Scopes:      oauthScopes,
		},
		APIHost: apiHost,
	}, nil
}
