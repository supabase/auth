package provider

import (
	"context"
	"errors"
	"fmt"
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

type orcUser struct {
	Emails struct {
		Email []struct {
			Email     string `json:"email"`
			IsPrimary bool   `json:"primary"`
			Verified  bool   `json:"verified"`
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
	} `json:"name"`
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
	var apiResponse orcUser
	var primaryEmail string
	var countryCodes []string
	var emails []Email
	isPrimaryExists := false

	// From Authorization code token exchange, orcID would also get returned as JSON
	// orcID would later be required for determining the route for user data retrieval
	// Ref: https://info.orcid.org/documentation/integration-and-api-faq/#easy-faq-2537
	orcID := fmt.Sprintf("%v", tok.Extra("orcid"))

	if orcID == "" {
		return nil, fmt.Errorf("Failed to extract orcID from OAuth2")
	}

	// API for reading public user information
	// API Docs: https://github.com/ORCID/orcid-model/tree/master/src/main/resources/record_3.0
	apiURL := defaultOrcidPublicApi + "/v3.0/" + orcID + "/record" // full JSON: https://github.com/ORCID/orcid-model/blob/master/src/main/resources/record_3.0/samples/read_samples/full-record-3.0.json

	if err := makeRequest(ctx, tok, g.Config, apiURL, &apiResponse); err != nil {
		return nil, err
	}
	if l := len(apiResponse.Emails.Email); l < 1 {
		return nil, errors.New("Unable to find email with Orcid provider. Please make sure that it's visible to public")
	}
	for _, v := range apiResponse.Addresses.Address {
		countryCodes = append(countryCodes, v.Country.Value)
	}
	for _, v := range apiResponse.Emails.Email {
		if v.IsPrimary {
			isPrimaryExists = true
			primaryEmail = v.Email
		}
		emails = append(emails, Email{
			Email:    v.Email,
			Verified: v.Verified,
			Primary:  v.IsPrimary,
		})
	}
	if !isPrimaryExists { // this means that primary email isn't visible to public
		// hack: make the first index to be primary on Supabase
		emails[0].Primary = true
		primaryEmail = emails[0].Email
	}
	u := orcidUser{
		ID:                  orcID,
		FirstName:           apiResponse.Name.FirstName.Value,
		LastName:            apiResponse.Name.LastName.Value,
		LocationCountryCode: strings.Join(countryCodes, ","),
		Email:               primaryEmail,
	}
	return &UserProvidedData{
		Metadata: &Claims{
			Issuer:        g.APIPath,
			Subject:       u.ID,
			Name:          strings.TrimSpace(u.FirstName + " " + u.LastName),
			Picture:       "",
			Email:         u.Email,
			EmailVerified: true,

			// To be deprecated
			AvatarURL:  "",
			FullName:   strings.TrimSpace(u.FirstName + " " + u.LastName),
			ProviderId: u.ID,
		},
		Emails: emails,
	}, nil
}
