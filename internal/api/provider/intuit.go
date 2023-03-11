package provider

import (
	"context"
	"errors"
	"strings"
	"github.com/supabase/gotrue/internal/conf"
	"golang.org/x/oauth2"
)
// For Intuit Sandbox use:
// const (
// 	defaultIntuitAuthBase = "appcenter.intuit.com/connect/oauth2"
// 	defaultIntiutTokenHost = "oauth.platform.intuit.com/oauth2/v1/tokens/bearer"
// 	defaultIntuitAPIBase  = "sandbox-accounts.platform.intuit.com/v1"
// )

const (
	defaultIntuitAuthBase = "appcenter.intuit.com/connect/oauth2"
	defaultIntiutTokenHost = "oauth.platform.intuit.com/oauth2/v1/tokens/bearer"
	defaultIntuitAPIBase  = "accounts.platform.intuit.com/v1"
)

type intuitProvider struct {
	*oauth2.Config
	APIPath string
}

type intuitUser struct {
	FirstName  string `json:"givenName"`
	LastName   string `json:"familyName"`
	Email 	   string `json:"email"`
	Verified   bool   `json:"email_verified"`
	Sub        string `json:"sub"`
}


func NewIntuitProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.Validate(); err != nil {
		return nil, err
	}

	authHost := chooseHost(ext.URL, defaultIntuitAuthBase)
	apiPath := chooseHost(ext.ApiURL, defaultIntuitAPIBase)
	tokenHost := chooseHost("", defaultIntiutTokenHost)

	oauthScopes := []string{"openid", "email", "profile"}

	if scopes != "" {
		oauthScopes = append(oauthScopes, strings.Split(scopes, ",")...)
	}

	return &intuitProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID,
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authHost,
				TokenURL: tokenHost,
			},
			RedirectURL: ext.RedirectURI,
			Scopes:      oauthScopes,
		},
		APIPath: apiPath,
	}, nil
}

func (g intuitProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return g.Exchange(context.Background(), code)
}

func (g intuitProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	var u intuitUser
	if err := makeRequest(ctx, tok, g.Config, g.APIPath+"/openid_connect/userinfo", &u); err != nil {
		return nil, err
	}

	if u.Email == "" {
		return nil, errors.New("unable to find email with Intuit provider")
	}

	FullName := u.FirstName + " " + u.LastName

	return &UserProvidedData{
		Metadata: &Claims{
			Issuer:        g.APIPath,
			Subject:       u.Sub,
			Name:          FullName,
			Email:         u.Email,
			EmailVerified: u.Verified,

			// To be deprecated
			FullName:   FullName,
			ProviderId: u.Sub,
		},
		Emails: []Email{{
			Email:    u.Email,
			Verified: u.Verified,
			Primary:  true,
		}},
	}, nil
}
