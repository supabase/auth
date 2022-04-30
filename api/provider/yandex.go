package provider

import (
	"context"
	"errors"
	"strings"

	"github.com/netlify/gotrue/conf"
	"golang.org/x/oauth2"
)

const (
	defaultYandexOauthApi = "oauth.yandex.ru"
	defaultYandexLoginApi = "login.yandex.ru"
)

type yandexProvider struct {
	*oauth2.Config
	APIPath string
}

type yandexUser struct {
	ID              string   `json:"id"`
	DefaultEmail    string   `json:"default_email"`
	FirstName       string   `json:"first_name"`
	LastName        string   `json:"last_name"`
	RealName        string   `json:"real_name"`
	Emails          []string `json:"emails"`
	Birthday        string   `json:"birthday"`
	DefaultAvatarId string   `json:"default_avatar_id"`
	IsAvatarEmpty   bool     `json:"is_avatar_empty"`
	Sex             string   `json:"sex"`
}

// NewYandexProvider creates a Orcid account provider.
func NewYandexProvider(ext conf.OAuthProviderConfiguration) (OAuthProvider, error) {
	if err := ext.Validate(); err != nil {
		return nil, err
	}

	authPath := chooseHost(ext.URL, defaultYandexOauthApi) + "/oauth"
	apiPath := chooseHost(ext.URL, defaultYandexLoginApi) + "/info"

	p := &yandexProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID,
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authPath + "/authorize",
				TokenURL: authPath + "/token",
			},
			RedirectURL: ext.RedirectURI,
		},
		APIPath: apiPath,
	}
	return p, nil
}

func (g yandexProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return g.Exchange(oauth2.NoContext, code)
}

func (g yandexProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	var u yandexUser
	// API for reading public user information
	// Docs: https://yandex.com/dev/id/doc/dg/api-id/reference/response.html
	apiURL := defaultYandexLoginApi + "/info"

	if err := makeRequest(ctx, tok, g.Config, apiURL, &u); err != nil {
		return nil, err
	}
	if l := len(u.Emails); l < 1 {
		return nil, errors.New("Unable to find email with Yandex provider")
	}
	var emails []Email
	for _, v := range u.Emails {
		primary := false
		if v == u.DefaultEmail {
			primary = true
		}
		emails = append(emails, Email{
			Email:    v,
			Verified: true, // yandex's resposible for verifying email
			Primary:  primary,
		})
	}
	return &UserProvidedData{
		Metadata: &Claims{
			Issuer:        g.APIPath,
			Subject:       u.ID,
			Name:          strings.TrimSpace(u.FirstName + " " + u.LastName),
			Picture:       "",
			Email:         u.DefaultEmail,
			EmailVerified: false,

			// To be deprecated
			AvatarURL:  "",
			FullName:   strings.TrimSpace(u.FirstName + " " + u.LastName),
			ProviderId: u.ID,
		},
		Emails: emails,
	}, nil
}
