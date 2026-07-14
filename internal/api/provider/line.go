package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/supabase/auth/internal/conf"
	"golang.org/x/oauth2"
)

// IssuerLINE is the issuer value found in LINE Login's OpenID Connect ID tokens.
const IssuerLINE = "https://access.line.me"

const (
	// defaultLineAuthBase hosts the authorization endpoint.
	defaultLineAuthBase = "access.line.me"
	// defaultLineAPIBase hosts the token endpoint.
	defaultLineAPIBase = "api.line.me"
)

type lineProvider struct {
	*oauth2.Config

	clientID string
	secret   string
}

type lineIDTokenClaims struct {
	jwt.RegisteredClaims

	Name    string `json:"name"`
	Picture string `json:"picture"`
	Email   string `json:"email"`
}

// NewLineProvider creates a LINE account provider.
//
// LINE Login is an OAuth 2.0 / OpenID Connect provider. The user's profile
// (name, picture) and email are returned as claims in the ID token. Unlike most
// OIDC providers, LINE signs its ID token using HS256 with the channel secret as
// the key (despite advertising ES256 in its discovery document), so the token is
// verified with the channel secret rather than via the provider's JWKS.
func NewLineProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.ValidateOAuth(); err != nil {
		return nil, err
	}

	oauthScopes := []string{
		"openid",
		"profile",
		"email",
	}

	if scopes != "" {
		oauthScopes = append(oauthScopes, strings.Split(scopes, ",")...)
	}

	authHost := chooseHost(ext.URL, defaultLineAuthBase)
	tokenHost := chooseHost(ext.URL, defaultLineAPIBase)

	return &lineProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID[0],
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthStyle: oauth2.AuthStyleInParams,
				AuthURL:   authHost + "/oauth2/v2.1/authorize",
				TokenURL:  tokenHost + "/oauth2/v2.1/token",
			},
			RedirectURL: ext.RedirectURI,
			Scopes:      oauthScopes,
		},
		clientID: ext.ClientID[0],
		secret:   ext.Secret,
	}, nil
}

func (p lineProvider) GetOAuthToken(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	return p.Exchange(ctx, code, opts...)
}

func (p lineProvider) RequiresPKCE() bool {
	return false
}

func (p lineProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, fmt.Errorf("line: no id_token present in token response")
	}

	var claims lineIDTokenClaims
	// LINE signs ID tokens with HS256 using the channel secret as the key. The
	// token is received directly from LINE's token endpoint over TLS during the
	// authorization code exchange.
	if _, err := jwt.ParseWithClaims(rawIDToken, &claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("line: unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(p.secret), nil
	},
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithIssuer(IssuerLINE),
		jwt.WithAudience(p.clientID),
	); err != nil {
		return nil, fmt.Errorf("line: failed to verify id_token: %w", err)
	}

	data := &UserProvidedData{}

	if claims.Email != "" {
		data.Emails = []Email{
			{
				Email: claims.Email,
				// LINE only returns the email claim once the user has granted
				// the email permission, and only verified emails are returned.
				Verified: true,
				Primary:  true,
			},
		}
	}

	data.Metadata = &Claims{
		Issuer:            IssuerLINE,
		Subject:           claims.Subject,
		Name:              claims.Name,
		PreferredUsername: claims.Name,
		Picture:           claims.Picture,
		ProviderId:        claims.Subject,

		// To be deprecated
		AvatarURL:   claims.Picture,
		FullName:    claims.Name,
		UserNameKey: claims.Name,
	}

	return data, nil
}
