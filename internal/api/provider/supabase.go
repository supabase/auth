package provider

import (
	"context"
	"errors"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/supabase/auth/internal/conf"
	"golang.org/x/oauth2"
)

// SupabaseProvider represents a Supabase OAuth provider
type SupabaseProvider struct {
	*oauth2.Config
	oidc *oidc.Provider
}

// NewSupabaseProvider creates a Supabase OAuth2 provider with OIDC discovery.
func NewSupabaseProvider(ctx context.Context, ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.ValidateOAuth(); err != nil {
		return nil, err
	}

	if ext.URL == "" {
		return nil, errors.New("unable to find URL for the Supabase provider, make sure config is set")
	}
	baseURL := strings.TrimSuffix(ext.URL, "/")

	// TODO(cemal) :: currently not being supported by supabase auth oauth2.1
	oauthScopes := []string{}
	if scopes != "" {
		oauthScopes = append(oauthScopes, strings.Split(scopes, ",")...)
	}

	// Use OIDC discovery to automatically find the authorization and token endpoints
	oidcProvider, err := oidc.NewProvider(ctx, baseURL)
	if err != nil {
		return nil, err
	}

	return &SupabaseProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID[0],
			ClientSecret: ext.Secret,
			Endpoint:     oidcProvider.Endpoint(),
			Scopes:       oauthScopes,
			RedirectURL:  ext.RedirectURI,
		},
		oidc: oidcProvider,
	}, nil
}

func (p SupabaseProvider) GetOAuthToken(code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	return p.Exchange(context.Background(), code, opts...)
}

func (p SupabaseProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	idToken := tok.Extra("id_token")
	if tok.AccessToken == "" || idToken == nil {
		return &UserProvidedData{}, nil
	}

	_, data, err := ParseIDToken(ctx, p.oidc, &oidc.Config{
		ClientID: p.ClientID,
	}, idToken.(string), ParseIDTokenOptions{
		AccessToken: tok.AccessToken,
	})
	if err != nil {
		return nil, err
	}

	return data, nil
}

// RequiresPKCE returns true as Supabase requires PKCE for OAuth
func (p *SupabaseProvider) RequiresPKCE() bool {
	return true
}
