package provider

import (
	"strings"

	"github.com/supabase/auth/internal/conf"
	"golang.org/x/oauth2"
)

// NewSlackProvider creates a Slack account provider.
func NewSlackLegacyProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.ValidateOAuth(); err != nil {
		return nil, err
	}

	apiPath := chooseHost(ext.URL, defaultSlackApiBase) + "/api"
	authPath := chooseHost(ext.URL, defaultSlackApiBase) + "/oauth"

	oauthScopes := []string{
		"profile",
		"email",
		"openid",
	}

	if scopes != "" {
		oauthScopes = append(oauthScopes, strings.Split(scopes, ",")...)
	}

	return &slackProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID[0],
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authPath + "/authorize",
				TokenURL: apiPath + "/oauth.access",
			},
			Scopes:      oauthScopes,
			RedirectURL: ext.RedirectURI,
		},
		APIPath: apiPath,
	}, nil
}