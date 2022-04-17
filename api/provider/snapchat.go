package provider

import (
	"context"
	"errors"
	"net/url"
	"strings"

	"github.com/netlify/gotrue/conf"
	"golang.org/x/oauth2"
)

const (
	defaultSnapchatAPIBase  = "accounts.snapchat.com"
	defaultSnapchatAuthBase = "auth.snapchat.com/oauth2/api/"
	defaultSnapchatKitBase  = "kit.snapchat.com"
)

type snapchatProvider struct {
	*oauth2.Config
	APIPath string
	KitPath string
}

type snapchatUser struct {
	Data struct {
		Me struct {
			ID      string `json:"externalId"`
			Name    string `json:"displayName"`
			Bitmoji struct {
				AvatarURL string `json:"avatar"`
				AvatarID  string `json:"id"`
			} `json:"bitmoji"`
			Email         string `json:"email"`
			EmailVerified bool   `json:"verified_email"`
		} `json:"me"`
	} `json:"data"`
}

// NewSnapchatProvider creates a Snapchat account provider.
func NewSnapchatProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.Validate(); err != nil {
		return nil, err
	}

	apiPath := chooseHost(ext.URL, defaultSnapchatAPIBase)
	// authPath := chooseHost(ext.URL, defaultSnapchatAuthBase)
	kitPath := chooseHost(ext.URL, defaultSnapchatKitBase)

	oauthScopes := []string{
		"https://auth.snapchat.com/oauth2/api/user.display_name",
		"https://auth.snapchat.com/oauth2/api/user.bitmoji.avatar",
		"https://auth.snapchat.com/oauth2/api/user.external_id",
	}

	if scopes != "" {
		oauthScopes = append(oauthScopes, strings.Split(scopes, " ")...)
	}

	return &snapchatProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID,
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  apiPath + "/accounts/oauth2/auth",
				TokenURL: apiPath + "/accounts/oauth2/token",
			},
			Scopes:      oauthScopes,
			RedirectURL: ext.RedirectURI,
		},
		APIPath: apiPath,
		KitPath: kitPath + "/v1/me",
	}, nil
}

func (g snapchatProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return g.Exchange(oauth2.NoContext, code)
}

func (g snapchatProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	var u snapchatUser
	params := url.Values{}
	params.Add("query", "{me{externalId displayName bitmoji{avatar id}}}")

	url := g.KitPath + "?" + params.Encode()
	if err := makeRequest(ctx, tok, g.Config, url, &u); err != nil {
		return nil, err
	}

	data := &UserProvidedData{}

	if u.Data.Me.Email != "" {
		data.Emails = append(data.Emails, Email{
			Email:    u.Data.Me.Email,
			Verified: u.Data.Me.EmailVerified,
			Primary:  true,
		})
	} else {
		data.Emails = append(data.Emails, Email{
			Email:    "Email not supported with Snapchat OAuth",
			Verified: u.Data.Me.EmailVerified,
			Primary:  true,
		})
	}

	if len(data.Emails) <= 0 {
		return nil, errors.New("Unable to find email with Snapchat provider")
	}

	data.Metadata = &Claims{
		Issuer:        g.APIPath,
		Subject:       u.Data.Me.ID,
		Name:          u.Data.Me.Name,
		Picture:       u.Data.Me.Bitmoji.AvatarURL,
		Email:         u.Data.Me.Email,
		EmailVerified: u.Data.Me.EmailVerified,
	}

	return data, nil
}
