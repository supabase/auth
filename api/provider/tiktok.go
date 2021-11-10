package provider

import (
	"context"
	"strings"

	"github.com/netlify/gotrue/conf"
	"golang.org/x/oauth2"
)

const (
	defaultTikTokAPIBase = "https://open-api.tiktok.com/"
)

type tiktokProvider struct {
	*oauth2.Config
	APIPath string
}

type tiktokUser struct {
	ID             string `json:"open_id"`
	UnionID        string `json:"union_id"`
	DisplayName    string `json:"display_name"`
	AvatarUrl      string `json:"avatar_url"`
	AvatarUrl100   string `json:"avatar_url_100"`
	AvatarUrl200   string `json:"avatar_url_200"`
	AvatarUrlLarge string `json:"avatar_large_url"`
}

// NewTikTokProvider creates a TikTok account provider.
func NewTikTokProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.Validate(); err != nil {
		return nil, err
	}

	apiPath := chooseHost(ext.URL, defaultTikTokAPIBase)

	oauthScopes := []string{
		"user.info.basic",
	}

	if scopes != "" {
		oauthScopes = append(oauthScopes, strings.Split(scopes, ",")...)
	}

	return &tiktokProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID,
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  apiPath + "/platform/oauth/connect",
				TokenURL: apiPath + "/oauth/access_token/",
			},
			Scopes:      oauthScopes,
			RedirectURL: ext.RedirectURI,
		},
		APIPath: apiPath,
	}, nil
}

func (g tiktokProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return g.Exchange(oauth2.NoContext, code)
}

func (g tiktokProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	var u tiktokUser
	if err := makeRequest(ctx, tok, g.Config, g.APIPath+"/user/info", &u); err != nil {
		return nil, err
	}

	return &UserProvidedData{
		Metadata: &Claims{
			Issuer:  g.APIPath,
			Subject: u.ID,
			Name:    u.DisplayName,
			Picture: u.AvatarUrl,

			// To be deprecated
			AvatarURL:  u.AvatarUrl,
			FullName:   u.DisplayName,
			ProviderId: u.ID,
		},
	}, nil
}
