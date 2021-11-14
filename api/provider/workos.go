package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/netlify/gotrue/conf"
	"golang.org/x/oauth2"
)

const (
	defaultWorkOSAPIBase = "https://api.workos.com"
)

type workosProvider struct {
	*oauth2.Config
	APIPath string
}

type workosUser struct {
	ID             string                 `json:"id"`
	ConnectionId   string                 `json:"connection_id"`
	ConnectionType string                 `json:"connection_type"`
	Email          string                 `json:"email"`
	FirstName      string                 `json:"first_name"`
	LastName       string                 `json:"last_name"`
	Object         string                 `json:"object"`
	IdpId          string                 `json:"idp_id"`
	RawAttributes  map[string]interface{} `json:"raw_attributes"`
}

// NewWorkOSProvider creates a WorkOS account provider.
func NewWorkOSProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.Validate(); err != nil {
		return nil, err
	}

	apiPath := chooseHost(ext.URL, defaultWorkOSAPIBase)

	oauthScopes := []string{}

	if scopes != "" {
		oauthScopes = append(oauthScopes, strings.Split(scopes, ",")...)
	}

	return &workosProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID,
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  apiPath + "/sso/authorize",
				TokenURL: apiPath + "/sso/token",
			},
			Scopes:      oauthScopes,
			RedirectURL: ext.RedirectURI,
		},
		APIPath: apiPath,
	}, nil
}

func (g workosProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return g.Exchange(oauth2.NoContext, code)
}

func (g workosProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	u := tok.Extra("profile").(workosUser)

	return &UserProvidedData{
		Metadata: &Claims{
			Issuer:  g.APIPath,
			Subject: u.ID,
			Name:    u.FirstName,
			Email:   u.Email,

			// To be deprecated
			FullName:   fmt.Sprintf("%s %s", u.FirstName, u.LastName),
			ProviderId: u.ID,
		},
		Emails: []Email{{
			Email:   u.Email,
			Primary: true,
		}},
	}, nil
}
