package provider

import (
	"context"
	"errors"
	"strings"

	"github.com/netlify/gotrue/conf"
	"golang.org/x/oauth2"
)

const (
	defaultLinkedInAPIBase = "api.linkedin.com"
)

type linkedinProvider struct {
	*oauth2.Config
	APIPath      string
	UserInfoURL  string
	UserEmailUrl string
}

// https://docs.microsoft.com/en-us/linkedin/consumer/integrations/self-serve/sign-in-with-linkedin?context=linkedin/consumer/context
type linkedinUser struct {
	ID        string       `json:"id"`
	FirstName linkedinName `json:"firstName"` // i tried to parse data but not sure
	LastName  linkedinName `json:"lastName"`  // i tried to parse data but not sure
	AvatarURL struct {     // I don't know if we can do better than that
		DisplayImage struct {
			Elements []struct {
				Identifiers []struct {
					Identifier string `json:"identifier"`
				} `json:"identifiers"`
			} `json:"elements"`
		} `json:"displayImage~"`
	} `json:"profilePicture"`
}

type linkedinLocale struct {
	Country  string `json:"country"`
	Language string `json:"language"`
}

type linkedinName struct {
	Localized       interface{}    `json:"localized"` // try to catch all possible value
	PreferredLocale linkedinLocale `json:"preferredLocale"`
}

type linkedinEmail struct {
	EmailAddress string `json:"emailAddress"`
}

type linkedinUserEmail struct {
	Handle       string        `json:"handle"`
	Handle_email linkedinEmail `json:"handle~"`
}

// NewLinkedinProvider creates a Linkedin account provider.
func NewLinkedInProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.Validate(); err != nil {
		return nil, err
	}

	// authHost := chooseHost(ext.URL, defaultLinkedinAuthBase)
	apiPath := chooseHost(ext.URL, defaultLinkedInAPIBase)

	oauthScopes := []string{
		"r_emailaddress",
		"r_liteprofile",
	}

	if scopes != "" {
		oauthScopes = append(oauthScopes, strings.Split(scopes, ",")...)
	}

	return &linkedinProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID,
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
	return g.Exchange(oauth2.NoContext, code)
}

func GetName(name linkedinName) string {
	key := name.PreferredLocale.Language + "_" + name.PreferredLocale.Country
	myMap := name.Localized.(map[string]interface{})
	return myMap[key].(string)
}

func (g linkedinProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	var u linkedinUser
	if err := makeRequest(ctx, tok, g.Config, g.APIPath+"/v2/me?projection=(id,firstName,lastName,profilePicture(displayImage~:playableStreams))", &u); err != nil {
		return nil, err
	}

	var email linkedinUserEmail
	if err := makeRequest(ctx, tok, g.Config, g.APIPath+"/v2/emailAddress?q=members&projection=(elements*(handle~))", &email); err != nil {
		return nil, err
	}

	emails := []Email{}

	if email.Handle_email.EmailAddress != "" {
		emails = append(emails, Email{
			Email:   email.Handle_email.EmailAddress,
			Primary: true,
		})
	}

	if len(emails) <= 0 {
		return nil, errors.New("Unable to find email with Linkedin provider")
	}

	return &UserProvidedData{
		Metadata: &Claims{
			Issuer:  g.APIPath,
			Subject: u.ID,
			Name:    strings.TrimSpace(GetName(u.FirstName) + " " + GetName(u.LastName)),
			Picture: u.AvatarURL.DisplayImage.Elements[0].Identifiers[0].Identifier,
			Email:   email.Handle_email.EmailAddress,

			// To be deprecated
			AvatarURL:  u.AvatarURL.DisplayImage.Elements[0].Identifiers[0].Identifier,
			FullName:   strings.TrimSpace(GetName(u.FirstName) + " " + GetName(u.LastName)),
			ProviderId: u.ID,
		},
		Emails: emails,
	}, nil
}
