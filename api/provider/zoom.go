package provider

import (
	"context"
	"strings"

	"github.com/netlify/gotrue/conf"
	"golang.org/x/oauth2"
)

const (
	defaultZoomAuthBase = "zoom.us"
	defaultZoomAPIBase  = "api.zoom.us"
)

type zoomProvider struct {
	*oauth2.Config
	APIPath string
}

type zoomUser struct {
	ID        string `json:"https://slack.com/user_id"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	AvatarURL string `json:"picture"`
}

// NewZoomProvider creates a Zoom account provider.
func NewZoomProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.Validate(); err != nil {
		return nil, err
	}

	apiPath := chooseHost(ext.URL, defaultZoomAPIBase) + "/v2"
	authPath := chooseHost(ext.URL, defaultZoomAuthBase) + "/oauth"

	oauthScopes := []string{
		"profile",
		"email",
		"openid",
	}

	if scopes != "" {
		oauthScopes = append(oauthScopes, strings.Split(scopes, ",")...)
	}

	return &zoomProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID,
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authPath + "/authorize",
				TokenURL: authPath + "/token",
			},
			Scopes:      oauthScopes,
			RedirectURL: ext.RedirectURI,
		},
		APIPath: apiPath,
	}, nil
}

func (g zoomProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return g.Exchange(oauth2.NoContext, code)
}

func (g zoomProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	var u zoomUser
	if err := makeRequest(ctx, tok, g.Config, g.APIPath+"/users/me", &u); err != nil {
		return nil, err
	}

	data := &UserProvidedData{
		Metadata: &Claims{
			Issuer:        g.APIPath,
			Subject:       u.ID,
			Name:          u.Name,
			Picture:       u.AvatarURL,
			Email:         u.Email,
			EmailVerified: true, // Slack dosen't provide data on if email is verified.

			// To be deprecated
			AvatarURL:  u.AvatarURL,
			FullName:   u.Name,
			ProviderId: u.ID,
		},
		Emails: []Email{{
			Email:    u.Email,
			Verified: true, // Slack dosen't provide data on if email is verified.
			Primary:  true,
		}},
	}

	return data, nil
}
