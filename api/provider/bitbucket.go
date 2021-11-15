package provider

import (
	"context"
	"errors"

	"github.com/netlify/gotrue/conf"
	"golang.org/x/oauth2"
)

const (
	defaultBitbucketAuthBase = "bitbucket.org"
	defaultBitbucketAPIBase  = "api.bitbucket.org"
)

type bitbucketProvider struct {
	*oauth2.Config
	APIPath string
}

type bitbucketUser struct {
	Name   string `json:"display_name"`
	ID     string `json:"uuid"`
	Avatar struct {
		Href string `json:"href"`
	} `json:"avatar"`
}

type bitbucketEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"is_primary"`
	Verified bool   `json:"is_confirmed"`
}

type bitbucketEmails struct {
	Values []bitbucketEmail `json:"values"`
}

// NewBitbucketProvider creates a Bitbucket account provider.
func NewBitbucketProvider(ext conf.OAuthProviderConfiguration) (OAuthProvider, error) {
	if err := ext.Validate(); err != nil {
		return nil, err
	}

	authHost := chooseHost(ext.URL, defaultBitbucketAuthBase)
	apiPath := chooseHost(ext.URL, defaultBitbucketAPIBase) + "/2.0"

	return &bitbucketProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID,
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authHost + "/site/oauth2/authorize",
				TokenURL: authHost + "/site/oauth2/access_token",
			},
			RedirectURL: ext.RedirectURI,
			Scopes:      []string{"account", "email"},
		},
		APIPath: apiPath,
	}, nil
}

func (g bitbucketProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return g.Exchange(oauth2.NoContext, code)
}

func (g bitbucketProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	var u bitbucketUser
	if err := makeRequest(ctx, tok, g.Config, g.APIPath+"/user", &u); err != nil {
		return nil, err
	}

	data := &UserProvidedData{}

	var emails bitbucketEmails
	if err := makeRequest(ctx, tok, g.Config, g.APIPath+"/user/emails", &emails); err != nil {
		return nil, err
	}

	if len(emails.Values) > 0 {
		for _, e := range emails.Values {
			if e.Email != "" {
				data.Emails = append(data.Emails, Email{
					Email:    e.Email,
					Verified: e.Verified,
					Primary:  e.Primary,
				})
			}
		}
	}

	if len(data.Emails) <= 0 {
		return nil, errors.New("Unable to find email with Bitbucket provider")
	}

	data.Metadata = &Claims{
		Issuer:  g.APIPath,
		Subject: u.ID,
		Name:    u.Name,
		Picture: u.Avatar.Href,

		// To be deprecated
		AvatarURL:  u.Avatar.Href,
		FullName:   u.Name,
		ProviderId: u.ID,
	}

	return data, nil
}
