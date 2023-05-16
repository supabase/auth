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

type GoogleOIDCProvider struct {
	*oidc.Provider
}

// ParseIDToken parses a Google issued OIDC ID token. You should verify the aud
// claim on your own!
func (p *GoogleOIDCProvider) ParseIDToken(ctx context.Context, idToken string) (*oidc.IDToken, *UserProvidedData, error) {
	verifier := p.Verifier(&oidc.Config{
		// aud claim check to be performed by other flows
		SkipClientIDCheck: true,
	})

	token, err := verifier.Verify(ctx, idToken)
	if err != nil {
		return nil, nil, err
	}

	var claims googleUser
	if err := token.Claims(&claims); err != nil {
		return nil, nil, err
	}

	var data UserProvidedData

	if claims.Email != "" {
		data.Emails = append(data.Emails, Email{
			Email:    claims.Email,
			Verified: claims.IsEmailVerified(),
			Primary:  true,
		})
	}

	if len(data.Emails) <= 0 {
		return nil, nil, errors.New("provider: Google ID token must contain an email address")
	}

	data.Metadata = &Claims{
		Issuer:        claims.Issuer,
		Subject:       claims.Subject,
		Name:          claims.Name,
		Picture:       claims.AvatarURL,
		Email:         claims.Email,
		EmailVerified: claims.IsEmailVerified(),

		// To be deprecated
		AvatarURL:  claims.AvatarURL,
		FullName:   claims.Name,
		ProviderId: claims.Subject,
	}

	if claims.HostedDomain != "" {
		data.Metadata.CustomClaims = map[string]any{
			"hd": claims.HostedDomain,
		}
	}

	return token, &data, nil
}

// NewGoogleOIDCProvider creates a new ODIC provider with
// https://accounts.google.com as the issuer.
func NewGoogleOIDCProvider(ctx context.Context) (*GoogleOIDCProvider, error) {
	provider, err := oidc.NewProvider(ctx, "https://accounts.google.com")
	if err != nil {
		return nil, err
	}

	return &GoogleOIDCProvider{provider}, nil
}

type googleProvider struct {
	*oauth2.Config

	oidc *GoogleOIDCProvider
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

	oidcProvider, err := NewGoogleOIDCProvider(ctx)
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

const oauthGoogleUserInfoEndpoint = "https://www.googleapis.com/userinfo/v2/me"

func (g googleProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	if idToken := tok.Extra("id_token"); idToken != nil {
		token, data, err := g.oidc.ParseIDToken(ctx, idToken.(string))
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
	if err := makeRequest(ctx, tok, g.Config, oauthGoogleUserInfoEndpoint, &u); err != nil {
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
		Issuer:        oauthGoogleUserInfoEndpoint,
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
