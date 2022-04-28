package provider

import (
	"context"
	"errors"
	"strings"

	"github.com/netlify/gotrue/conf"
	"golang.org/x/oauth2"
)

const (
	defaultOrcidPublicApi = "pub.orcid.org"
	defaultOrcidApi       = "orcid.org"
)

type orcidProvider struct {
	*oauth2.Config
	APIPath string
}

type orcidUser struct {
	ID                  string `json:"orcid"`
	FirstName           string `json:"firstname"`
	LastName            string `json:"lastname"`
	Email               string `json:"email"`
	LocationCountryCode string `json:"loccountrycode"`
}

// NewOrcidProvider creates a Orcid account provider.
func NewOrcidProvider(ext conf.OAuthProviderConfiguration) (OAuthProvider, error) {
	if err := ext.Validate(); err != nil {
		return nil, err
	}

	authPath := chooseHost(ext.URL, defaultOrcidApi) + "/oauth"
	apiPath := chooseHost(ext.URL, defaultOrcidPublicApi) + "/v3.0"

	p := &orcidProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID,
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authPath + "/authorize",
				TokenURL: authPath + "/token",
			},
			RedirectURL: ext.RedirectURI,
		},
		APIPath: apiPath,
	}
	return p, nil
}

func (g orcidProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return g.Exchange(oauth2.NoContext, code)
}

func (g orcidProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	// API for reading public user information
	// Docs: https://github.com/ORCID/orcid-model/tree/master/src/main/resources/record_3.0
	apiURL := defaultOrcidPublicApi + "/v3.0/" + g.Config.ClientID + "/record"

	apiResponse := struct {
		Emails struct {
			Email []struct {
				Value string `json:"email"`
			} `json:"email"`
		} `json:"emails"`
		Addresses struct {
			Address []struct {
				Country struct {
					Value string `json:"value"`
				} `json:"country"`
			} `json:"address"`
		} `json:"addresses"`
		Name struct {
			FirstName struct {
				Value string `json:"value"`
			} `json:"given-names"`
			LastName struct {
				Value string `json:"value"`
			} `json:"family-name"`
			OrcID string `json:"path"`
		} `json:"name"`
	}{}
	if err := makeRequest(ctx, tok, g.Config, apiURL, &apiResponse); err != nil {
		return nil, err
	}
	if l := len(apiResponse.Emails.Email); l < 1 {
		return nil, errors.New("Unable to find email with Orcid provider. Please make sure that it's visible to public")
	}
	var countryCodes []string
	for _, v := range apiResponse.Addresses.Address {
		countryCodes = append(countryCodes, v.Country.Value)
	}
	var emails []Email
	for i, v := range apiResponse.Emails.Email {
		primary := false
		if i == 0 {
			primary = true
		}
		emails = append(emails, Email{
			Email:    v.Value,
			Verified: false,
			Primary:  primary,
		})
	}
	u := orcidUser{
		ID:                  apiResponse.Name.OrcID,
		FirstName:           apiResponse.Name.FirstName.Value,
		LastName:            apiResponse.Name.LastName.Value,
		LocationCountryCode: strings.Join(countryCodes, ","),
		Email:               emails[0].Email,
	}
	return &UserProvidedData{
		Metadata: &Claims{
			Issuer:        g.APIPath,
			Subject:       u.ID,
			Name:          strings.TrimSpace(u.FirstName + " " + u.LastName),
			Picture:       "",
			Email:         u.Email,
			EmailVerified: false,

			// To be deprecated
			AvatarURL:  "",
			FullName:   strings.TrimSpace(u.FirstName + " " + u.LastName),
			ProviderId: u.ID,
		},
		Emails: emails,
	}, nil
}
