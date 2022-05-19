package provider

import (
	"context"
	"errors"
	"strings"

	"github.com/netlify/gotrue/conf"
	"golang.org/x/oauth2"
)

const (
	defaultAzureAuthBase = "login.microsoftonline.com/common"
	defaultAzureAPIBase  = "graph.microsoft.com"
)

type azureProvider struct {
	*oauth2.Config
	APIPath string
}

type azureUser struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	Sub   string `json:"sub"`
}

type azureEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"is_primary"`
	Verified bool   `json:"is_confirmed"`
}

type azureGroupResponse struct {
	Value []azureGroup `json:"value"`
}

type azureGroup struct {
	DisplayName string `json:"displayName"`
}

// NewAzureProvider creates a Azure account provider.
func NewAzureProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.Validate(); err != nil {
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
			ClientID:     ext.ClientID,
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
	return g.Exchange(oauth2.NoContext, code)
}

func (g azureProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	var u azureUser
	if err := makeRequest(ctx, tok, g.Config, g.APIPath+"/oidc/userinfo", &u); err != nil {
		return nil, err
	}

	if u.Email == "" {
		return nil, errors.New("Unable to find email with Azure provider")
	}

	var groupsResponse azureGroupResponse
	var groups []string
	if err := makeRequest(ctx, tok, g.Config, g.APIPath+"/v1.0/me/memberOf", &groupsResponse); err == nil {
		for _, group := range groupsResponse.Value {
			groups = append(groups, group.DisplayName)
		}
	}

	return &UserProvidedData{
		Metadata: &Claims{
			Issuer:        g.APIPath,
			Subject:       u.Sub,
			Name:          u.Name,
			Email:         u.Email,
			EmailVerified: true,
			Groups:		   groups,

			// To be deprecated
			FullName:   u.Name,
			ProviderId: u.Sub,
		},
		Emails: []Email{{
			Email:    u.Email,
			Verified: true,
			Primary:  true,
		}},
	}, nil
}
