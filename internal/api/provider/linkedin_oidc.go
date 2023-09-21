package provider

import (
	"context"
	"strings"

	"github.com/supabase/gotrue/internal/conf"
	"golang.org/x/oauth2"
)

const (
	defaultLinkedinOIDCAPIBase = "api.linkedin.com"
)

type linkedinOIDCProvider struct {
	*oauth2.Config
	APIPath      string
	UserInfoURL  string
	UserEmailUrl string
}

// See https://learn.microsoft.com/en-us/linkedin/consumer/integrations/self-serve/sign-in-with-linkedin-v2
// for retrieving a member's profile. This requires the profile, openid, and email scope.
type linkedinOIDCUser struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	EmailVerified bool   `json:"email_verified"`
}

// NewLinkedinOIDCProvider creates a Linkedin account provider via OIDC.
func NewLinkedinOIDCProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.ValidateOAuth(); err != nil {
		return nil, err
	}

	apiPath := chooseHost(ext.URL, defaultLinkedinOIDCAPIBase)

	oauthScopes := []string{
		"openid",
		"email",
		"profile",
	}

	if scopes != "" {
		oauthScopes = append(oauthScopes, strings.Split(scopes, ",")...)
	}

	return &linkedinOIDCProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID[0],
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  apiPath + "/oauth/v2/authorization",
				TokenURL: apiPath + "/oauth/v2/accessToken",
			},
			Scopes:      oauthScopes,
			RedirectURL: ext.RedirectURI,
		},
		APIPath: apiPath,
	}, nil
}

func (g linkedinOIDCProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return g.Exchange(context.Background(), code)
}

func (g linkedinOIDCProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	var u linkedinOIDCUser
	if err := makeRequest(ctx, tok, g.Config, g.APIPath+"/v2/userinfo", &u); err != nil {
		return nil, err
	}

	return &UserProvidedData{
		Metadata: &Claims{
			Issuer:        g.APIPath,
			Subject:       u.Sub,
			Name:          strings.TrimSpace(u.GivenName + " " + u.FamilyName),
			Picture:       u.Picture,
			Email:         u.Email,
			EmailVerified: u.EmailVerified,

			// To be deprecated
			AvatarURL:  u.Picture,
			FullName:   strings.TrimSpace(u.GivenName + " " + u.FamilyName),
			ProviderId: u.Sub,
		},
		Emails: []Email{{
			Email:    u.Email,
			Verified: u.EmailVerified,
			Primary:  true,
		}},
	}, nil
}
