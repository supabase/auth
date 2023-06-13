package provider

import (
	"context"
	"errors"
	"strings"

	"github.com/supabase/gotrue/internal/conf"
	"golang.org/x/oauth2"
)

const IssuerAzure = "https://login.microsoftonline.com/common/v2.0"

const (
	defaultAzureAuthBase = "login.microsoftonline.com/common"
	defaultAzureAPIBase  = "graph.microsoft.com"
)

type azureProvider struct {
	*oauth2.Config
	APIPath string
}

type azureUser struct {
	Name       string   `json:"name"`
	Email      string   `json:"email"`
	Sub        string   `json:"sub"`
	OtherMails []string `json:"otherMails"`
}

// NewAzureProvider creates a Azure account provider.
func NewAzureProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.ValidateOAuth(); err != nil {
		return nil, err
	}

	authHost := chooseHost(ext.URL, defaultAzureAuthBase)
	apiPath := chooseHost(ext.ApiURL, defaultAzureAPIBase)

	oauthScopes := []string{"openid"}

	if scopes != "" {
		oauthScopes = append(oauthScopes, strings.Split(scopes, ",")...)
	}

	return &azureProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID[0],
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authHost + "/oauth2/v2.0/authorize",
				TokenURL: authHost + "/oauth2/v2.0/token",
			},
			RedirectURL: ext.RedirectURI,
			Scopes:      oauthScopes,
		},
		APIPath: apiPath,
	}, nil
}

func (g azureProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return g.Exchange(context.Background(), code)
}

func (g azureProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	var u azureUser
	if err := makeRequest(ctx, tok, g.Config, g.APIPath+"/oidc/userinfo", &u); err != nil {
		return nil, err
	}

	var data UserProvidedData

	data.Metadata = &Claims{
		Issuer:  g.APIPath,
		Subject: u.Sub,
		Name:    u.Name,

		// To be deprecated
		FullName:   u.Name,
		ProviderId: u.Sub,
	}

	if u.Email != "" {
		data.Emails = append(data.Emails, Email{
			Email:    u.Email,
			Verified: true,
		})
	}

	if u.OtherMails != nil {
		for _, mail := range u.OtherMails {
			if mail != "" {
				data.Emails = append(data.Emails, Email{
					Email:    mail,
					Verified: false,
				})
			}
		}
	}

	if len(data.Emails) == 0 {
		return nil, errors.New("unable to find email with Azure provider")
	}

	data.Emails[0].Primary = true

	data.Metadata.Email = data.Emails[0].Email
	data.Metadata.EmailVerified = data.Emails[0].Verified

	return &data, nil
}
