package provider

import (
	"context"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/supabase/auth/internal/conf"
	"golang.org/x/oauth2"
)

const (
	defaultVercelMarketplaceAPIBase = "api.vercel.com"
	IssuerVercelMarketplace         = "https://marketplace.vercel.com"
)

type vercelMarketplaceProvider struct {
	*oauth2.Config
	oidc    *oidc.Provider
	APIPath string
}

// NewVercelMarketplaceProvider creates a VercelMarketplace account provider via OIDC.
func NewVercelMarketplaceProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.ValidateOAuth(); err != nil {
		return nil, err
	}

	apiPath := chooseHost(ext.URL, defaultVercelMarketplaceAPIBase)

	oauthScopes := []string{}

	if scopes != "" {
		oauthScopes = append(oauthScopes, strings.Split(scopes, ",")...)
	}

	oidcProvider, err := oidc.NewProvider(context.Background(), IssuerVercelMarketplace)
	if err != nil {
		return nil, err
	}

	return &vercelMarketplaceProvider{
		oidc: oidcProvider,
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

func (g vercelMarketplaceProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return g.Exchange(context.Background(), code)
}

func (g vercelMarketplaceProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	idToken := tok.Extra("id_token")
	if tok.AccessToken == "" || idToken == nil {
		return &UserProvidedData{}, nil
	}

	_, data, err := ParseIDToken(ctx, g.oidc, &oidc.Config{
		ClientID: g.ClientID,
	}, idToken.(string), ParseIDTokenOptions{
		AccessToken: tok.AccessToken,
	})
	if err != nil {
		return nil, err
	}
	return data, nil
}
