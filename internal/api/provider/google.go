package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sirupsen/logrus"
	"github.com/supabase/gotrue/internal/conf"
	"golang.org/x/oauth2"
)

type googleUser struct {
	ID            string `json:"id"`
	Subject       string `json:"sub"`
	Issuer        string `json:"iss"`
	Name          string `json:"name"`
	AvatarURL     string `json:"picture"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	EmailVerified bool   `json:"email_verified"`
	HostedDomain  string `json:"hd"`
}

func (u googleUser) IsEmailVerified() bool {
	return u.VerifiedEmail || u.EmailVerified
}

const IssuerGoogle = "https://accounts.google.com"

var internalIssuerGoogle = IssuerGoogle

type googleProvider struct {
	*oauth2.Config

	oidc *oidc.Provider
}

// NewGoogleProvider creates a Google OAuth2 identity provider.
func NewGoogleProvider(ctx context.Context, ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.Validate(); err != nil {
		return nil, err
	}

	if ext.URL != "" {
		logrus.Warn("Google OAuth provider has URL config set which is ignored (check GOTRUE_EXTERNAL_GOOGLE_URL)")
	}

	oauthScopes := []string{
		"email",
		"profile",
	}

	if scopes != "" {
		oauthScopes = append(oauthScopes, strings.Split(scopes, ",")...)
	}

	oidcProvider, err := oidc.NewProvider(ctx, internalIssuerGoogle)
	if err != nil {
		return nil, err
	}

	return &googleProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID,
			ClientSecret: ext.Secret,
			Endpoint:     oidcProvider.Endpoint(),
			Scopes:       oauthScopes,
			RedirectURL:  ext.RedirectURI,
		},
		oidc: oidcProvider,
	}, nil
}

func (g googleProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return g.Exchange(context.Background(), code)
}

const UserInfoEndpointGoogle = "https://www.googleapis.com/userinfo/v2/me"

var internalUserInfoEndpointGoogle = UserInfoEndpointGoogle

func (g googleProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	if idToken := tok.Extra("id_token"); idToken != nil {
		token, data, err := ParseIDToken(ctx, g.oidc, nil, idToken.(string), ParseIDTokenOptions{
			AccessToken: tok.AccessToken,
		})
		if err != nil {
			return nil, err
		}

		matchesAudience := false
		for _, aud := range token.Audience {
			if g.Config.ClientID == aud {
				matchesAudience = true
				break
			}
		}

		if !matchesAudience {
			return nil, fmt.Errorf("provider: Google ID token issued for audience(s) %q but expected %q", strings.Join(token.Audience, ", "), g.Config.ClientID)
		}

		return data, err
	}

	// This whole section offers legacy support in case the Google OAuth2
	// flow does not return an ID Token for the user, which appears to
	// always be the case.
	logrus.Info("Using Google OAuth2 user info endpoint, an ID token was not returned by Google")

	var u googleUser
	if err := makeRequest(ctx, tok, g.Config, internalUserInfoEndpointGoogle, &u); err != nil {
		return nil, err
	}

	var data UserProvidedData

	if u.Email != "" {
		data.Emails = append(data.Emails, Email{
			Email:    u.Email,
			Verified: u.IsEmailVerified(),
			Primary:  true,
		})
	}

	if len(data.Emails) <= 0 {
		return nil, errors.New("provider: Google OAuth2 user info endpoint did not return an email address")
	}

	data.Metadata = &Claims{
		Issuer:        internalUserInfoEndpointGoogle,
		Subject:       u.ID,
		Name:          u.Name,
		Picture:       u.AvatarURL,
		Email:         u.Email,
		EmailVerified: u.IsEmailVerified(),

		// To be deprecated
		AvatarURL:  u.AvatarURL,
		FullName:   u.Name,
		ProviderId: u.ID,
	}

	return &data, nil
}

// ResetGoogleProvider should only be used in tests!
func ResetGoogleProvider() {
	internalIssuerGoogle = IssuerGoogle
	internalUserInfoEndpointGoogle = UserInfoEndpointGoogle
}

// OverrideGoogleProvider should only be used in tests!
func OverrideGoogleProvider(issuer, userInfo string) {
	internalIssuerGoogle = issuer
	internalUserInfoEndpointGoogle = userInfo
}
