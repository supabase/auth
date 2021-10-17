package provider

import (
	"context"
	"errors"
	"strings"

	"github.com/netlify/gotrue/conf"
	"golang.org/x/oauth2"
)

const (
	defaultLinkedinAPIBase  = "api.linkedin.com"
	endpointProfile = "/v2/me?projection=(id,firstName,lastName,profilePicture(displayImage~:playableStreams))"
	endpointEmail = "/v2/emailAddress?q=members&projection=(elements*(handle~))"
)

type linkedinProvider struct {
	*oauth2.Config
	APIPath string
	UserInfoURL   string
	UserEmailUrl   string
}


// This is the json returned by api for profile
// {
//  "firstName":{
// 	"localized":{
// 	   "en_US":"Tina"
// 	},
// 	"preferredLocale":{
// 	   "country":"US",
// 	   "language":"en"
// 	}
//  },
//  "lastName":{
// 	"localized":{
// 	   "en_US":"Belcher"
// 	},
// 	"preferredLocale":{
// 	   "country":"US",
// 	   "language":"en"
// 	}
//  },
// }

// return format for avatarUrl
// {"displayImage~" : { elements: [{identifiers: [ {identifier: "URL"}]}]}}


// https://docs.microsoft.com/en-us/linkedin/consumer/integrations/self-serve/sign-in-with-linkedin?context=linkedin/consumer/context
type linkedinLocale struct {
	Country	      string `json:"country"`
	Language	  string `json:"language"`
}

type linkedinLocalized struct {
	En_US	  string `json:"en_US"` // how to modelize catch all for lang ?
}
type linkedinName struct {
	Localized           linkedinLocalized `json:"localized"`
	PreferredLocale     linkedinLocale `json:"preferredLocale"`
}

type 
type linkedinUser struct {
	ID            string `json:"id"`
	FirstName     linkedinName `json:"firstName"` // i tried to parse data but not sure
	LastName      linkedinName `json:"lastName"` // i tried to parse data but not sure
	AvatarURL     struct { // I don't know if we can do better than that
		DisplayImage struct {
			Elements []struct {
				Identifiers []struct {
						Identifier            string `json:"identifier"`
					} `json:"identifiers"`
				} `json:"elements"`
		} `json:"displayImage~"`
	} `json:"profilePicture"`
}


// This is the json returned by api for email
// {
//     "handle": "urn:li:emailAddress:3775708763",
//     "handle~": {
//         "emailAddress": "hsimpson@linkedin.com"
//     }
// }

type linkedinEmail struct {
	EmailAddress   string `json:"emailAddress"`
}

type linkedinUserEmail struct {
	Handle   string `json:"handle"`
	Handle_email   linkedinEmail `json:"handle~"`
}

// NewLinkedinProvider creates a Linkedin account provider.
func NewLinkedinProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.Validate(); err != nil {
		return nil, err
	}

	// authHost := chooseHost(ext.URL, defaultLinkedinAuthBase)
	apiPath := chooseHost(ext.URL, defaultLinkedinAPIBase)

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
				AuthURL:  authHost + "/oauth/v2/authorization",
				TokenURL: authHost + "/oauth/v2/accessToken",
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

func GetName(name linkedinName) (string) {
	return name.localized[name.preferredLocale.language + "_" + name.preferredLocale.country]
}

nameRes.localized[`${nameRes.preferredLocale.language}_${nameRes.preferredLocale.country}`]

func (g linkedinProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	var u linkedinUser
	if err := makeRequest(ctx, tok, g.Config, g.APIPath + endpointProfile, &u); err != nil {
		return nil, err
	}

	data := &UserProvidedData{}

	var email githubUserEmail
	if err := makeRequest(ctx, tok, g.Config, g.APIHost + endpointEmail, &email); err != nil {
		return nil, err
	}

	if email != "" {
		data.Emails = append(data.Emails, Email{
			Email:    email.Handle_email.EmailAddress,
			Verified: true,
			Primary:  true,
		})
	}

	if len(data.Emails) <= 0 {
		return nil, errors.New("Unable to find email with Linkedin provider")
	}

	data.Metadata = &Claims{
		Issuer:        g.APIPath,
		Subject:       u.ID,
		Name:          strings.TrimSpace(GetName(u.FirstName) + " " + GetName(u.FirstName)),
		Picture:       u.AvatarURL.DisplayImage.Elements[0].Identifiers[0].Identifier,
		Email:         email.Handle_email.EmailAddress,
		EmailVerified: true,

		// To be deprecated
		AvatarURL:  u.AvatarURL,
		FullName:   strings.TrimSpace(GetName(u.FirstName) + " " + GetName(u.FirstName)),
		ProviderId: u.ID,
	}

	return data, nil
}
