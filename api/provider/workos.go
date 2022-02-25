package provider

import (
	"context"
	"net/url"
	"strings"

	"github.com/netlify/gotrue/conf"
	"golang.org/x/oauth2"
)

const (
	defaultWorkOSAPIBase = "api.workos.com"
)

type workosProvider struct {
	*oauth2.Config
	APIPath         string
	AuthCodeOptions []oauth2.AuthCodeOption
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
func NewWorkOSProvider(ext conf.OAuthProviderConfiguration, query *url.Values) (OAuthProvider, error) {
	if err := ext.Validate(); err != nil {
		return nil, err
	}
	apiPath := chooseHost(ext.URL, defaultWorkOSAPIBase)

	// Attach custom query parameters to the WorkOS authorization URL.
	// See https://workos.com/docs/reference/sso/authorize/get.
	authCodeOptions := make([]oauth2.AuthCodeOption, 0)
	if query != nil {
		if connection := query.Get("connection"); connection != "" {
			authCodeOptions = append(authCodeOptions, oauth2.SetAuthURLParam("connection", connection))
		} else if organization := query.Get("organization"); organization != "" {
			authCodeOptions = append(authCodeOptions, oauth2.SetAuthURLParam("organization", organization))
		} else if provider := query.Get("provider"); provider != "" {
			authCodeOptions = append(authCodeOptions, oauth2.SetAuthURLParam("provider", provider))
		}

		if login_hint := query.Get("login_hint"); login_hint != "" {
			authCodeOptions = append(authCodeOptions, oauth2.SetAuthURLParam("login_hint", login_hint))
		}
	}

	return &workosProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID,
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  apiPath + "/sso/authorize",
				TokenURL: apiPath + "/sso/token",
			},
			RedirectURL: ext.RedirectURI,
		},
		APIPath:         apiPath,
		AuthCodeOptions: authCodeOptions,
	}, nil
}

func (g workosProvider) AuthCodeURL(state string, args ...oauth2.AuthCodeOption) string {
	opts := append(args, g.AuthCodeOptions...)
	return g.Config.AuthCodeURL(state, opts...)
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
			FullName:   strings.TrimSpace(u.FirstName + " " + u.LastName),
			ProviderId: u.ID,
		},
		Emails: []Email{{
			Email:   u.Email,
			Primary: true,
		}},
	}, nil
}
