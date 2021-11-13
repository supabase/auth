package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/netlify/gotrue/conf"
	"golang.org/x/oauth2"
)

const (
	defaultWorkOSAPIBase = "https://api.workos.com"
)

type workosProvider struct {
	*oauth2.Config
	APIPath string
}

/*
{
  "id": "prof_01DMC79VCBZ0NY2099737PSVF1",
  "connection_id": "conn_01E4ZCR3C56J083X43JQXF3JK5",
  "connection_type": "okta",
  "email": "todd@foo-corp.com",
  "first_name": "Todd",
  "idp_id": "00u1a0ufowBJlzPlk357",
  "last_name": "Rundgren",
  "object": "profile",
  "raw_attributes": {...}
}
*/
type workosUser struct {
	ID             string                 `json:"id"`
	ConnectionId   string                 `json:"connection_id"`
	ConnectionType string                 `json:"connection_type"`
	Email          string                 `json:"email"`
	FirstName      string                 `json:"first_name"`
	LastName       string                 `json:"last_name"`
	Object         string                 `json:"object"`
	IdpId          string                 `json:"idp_id"`
	RawAttributes  map[string]interface{} `json:"raw_attributes"`
}

// NewWorkOSProvider creates a WorkOS account provider.
func NewWorkOSProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.Validate(); err != nil {
		return nil, err
	}

	apiPath := chooseHost(ext.URL, defaultWorkOSAPIBase)

	oauthScopes := []string{}

	if scopes != "" {
		oauthScopes = append(oauthScopes, strings.Split(scopes, ",")...)
	}

	return &workosProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID,
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  apiPath + "/sso/authorize",
				TokenURL: apiPath + "/sso/token",
			},
			Scopes:      oauthScopes,
			RedirectURL: ext.RedirectURI,
		},
		APIPath: apiPath,
	}, nil
}

func (g workosProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	// TODO rework this as the TokenURL returns only an access token and the profile
	return g.Exchange(oauth2.NoContext, code)
}

func (g workosProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	var u workosUser
	// TODO rework this as the only way to get profile is with TokenURL
	if err := makeRequest(ctx, tok, g.Config, g.APIPath+"/sso/token", &u); err != nil {
		return nil, err
	}

	return &UserProvidedData{
		Metadata: &Claims{
			Issuer:  g.APIPath,
			Subject: u.ID,
			Name:    u.FirstName,
			Email:   u.Email,

			// To be deprecated
			FullName:   fmt.Sprintf("%s %s", u.FirstName, u.LastName),
			ProviderId: u.ID,
		},
		Emails: []Email{{
			Email:   u.Email,
			Primary: true,
		}},
	}, nil
}
