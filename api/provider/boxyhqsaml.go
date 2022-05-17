package provider

import (
	"context"
	"errors"
	"strings"

	"github.com/netlify/gotrue/conf"
	"golang.org/x/oauth2"
)

const (
	defaultBoxyHQSAMLAPIBase = "jackson-demo.boxyhq.com"
)

type BoxyHQSAMLProvider struct {
	*oauth2.Config
	APIPath         string
	AuthCodeOptions []oauth2.AuthCodeOption
}

// See https://boxyhq.com/docs/jackson/saml-flow#33-profile-request.
type BoxyHQSAMLUser struct {
	ID        string                 `mapstructure:"id"`
	Email     string                 `mapstructure:"email"`
	FirstName string                 `mapstructure:"firstName"`
	LastName  string                 `mapstructure:"lastName"`
	Raw       map[string]interface{} `mapstructure:"raw"`
	Requested map[string]interface{} `mapstructure:"requested"`
}

// NewJacksonProvider creates a Jackson account provider.
func NewBoxyHQSAMLProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.Validate(); err != nil {
		return nil, err
	}
	apiPath := chooseHost(ext.URL, defaultBoxyHQSAMLAPIBase)

	oauthScopes := []string{}
	if scopes != "" {
		oauthScopes = append(oauthScopes, strings.Split(scopes, ",")...)
	}

	return &BoxyHQSAMLProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID,
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  apiPath + "/api/oauth/authorize",
				TokenURL: apiPath + "/api/oauth/token",
			},
			Scopes:      oauthScopes,
			RedirectURL: ext.RedirectURI,
		},
		APIPath: apiPath,
		// AuthCodeOptions: authCodeOptions,
	}, nil
}

func (g BoxyHQSAMLProvider) AuthCodeURL(state string, args ...oauth2.AuthCodeOption) string {
	opts := append(args, g.AuthCodeOptions...)
	return g.Config.AuthCodeURL(state, opts...)
}

func (g BoxyHQSAMLProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("client_id", strings.Join(g.Scopes, "")),
		oauth2.SetAuthURLParam("client_secret", g.ClientSecret),
	}
	return g.Exchange(oauth2.NoContext, code, opts...)
}

func (g BoxyHQSAMLProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	var u BoxyHQSAMLUser
	if err := makeRequest(ctx, tok, g.Config, g.APIPath+"/api/oauth/userinfo", &u); err != nil {
		return nil, err
	}

	if u.Email == "" {
		return nil, errors.New("Unable to find email with boxyhqsaml provider")
	}

	return &UserProvidedData{
		Metadata: &Claims{
			Issuer:        g.APIPath,
			Subject:       u.ID,
			Name:          strings.TrimSpace(u.FirstName + " " + u.LastName),
			Email:         u.Email,
			EmailVerified: true,
			CustomClaims: map[string]interface{}{
				"Raw":       u.Raw,
				"Requested": u.Requested,
			},

			// To be deprecated
			FullName:   strings.TrimSpace(u.FirstName + " " + u.LastName),
			ProviderId: u.ID,
		},
		Emails: []Email{{
			Email:    u.Email,
			Verified: true,
			Primary:  true,
		}},
	}, nil
}
