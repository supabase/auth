package provider

import (
	"context"
	"strings"

	"log"
	"github.com/supabase/gotrue/internal/conf"
	"golang.org/x/oauth2"
)

const (
	defaultLinkedinAPIBase = "api.linkedin.com"
)

type linkedinProvider struct {
	*oauth2.Config
	APIPath      string
	UserInfoURL  string
	UserEmailUrl string
}

// See https://docs.microsoft.com/en-us/linkedin/consumer/integrations/self-serve/sign-in-with-linkedin?context=linkedin/consumer/context
// for retrieving a member's profile. This requires the r_liteprofile scope.
type linkedinUser struct {
	Sub        		string       `json:"sub"`
	Email					string			 `json:"email"`
	Name					string			 `json:"name"`
	Picture				string			 `json:"picture"`
	GivenName			string			 `json:"given_name"`
	FamilyName		string			 `json:"family_name"`
	EmailVerified	bool			 	 `json:"email_verified"`
}

func (u *linkedinUser) getAvatarUrl() string {
	avatarURL := u.Picture
	return avatarURL
}

type linkedinName struct {
	Localized       interface{}    `json:"localized"`
	PreferredLocale linkedinLocale `json:"preferredLocale"`
}

type linkedinLocale struct {
	Country  string `json:"country"`
	Language string `json:"language"`
}

// See https://docs.microsoft.com/en-us/linkedin/consumer/integrations/self-serve/sign-in-with-linkedin?context=linkedin/consumer/context#retrieving-member-email-address
// for retrieving a member email address. This requires the r_email_address scope.
type linkedinElements struct {
	Elements []struct {
		Handle      string `json:"handle"`
		HandleTilde struct {
			EmailAddress string `json:"emailAddress"`
		} `json:"handle~"`
	} `json:"elements"`
}

// NewLinkedinProvider creates a Linkedin account provider.
func NewLinkedinProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.ValidateOAuth(); err != nil {
		return nil, err
	}

	apiPath := chooseHost(ext.URL, defaultLinkedinAPIBase)

	oauthScopes := []string{
		"openid",
		"email",
		"profile",
	}

	if scopes != "" {
		oauthScopes = append(oauthScopes, strings.Split(scopes, ",")...)
	}

	return &linkedinProvider{
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

func (g linkedinProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return g.Exchange(context.Background(), code)
}

func GetName(name linkedinName) string {
	key := name.PreferredLocale.Language + "_" + name.PreferredLocale.Country
	myMap := name.Localized.(map[string]interface{})
	return myMap[key].(string)
}

func (g linkedinProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	var u linkedinUser
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
			Email: u.Email,
			Verified: u.EmailVerified,
			Primary: true,
		}},
	}, nil
}
