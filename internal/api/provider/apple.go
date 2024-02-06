package provider

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sirupsen/logrus"
	"github.com/supabase/auth/internal/conf"
	"golang.org/x/oauth2"
)

const IssuerApple = "https://appleid.apple.com"

// AppleProvider stores the custom config for apple provider
type AppleProvider struct {
	*oauth2.Config
	oidc *oidc.Provider
}

type IsPrivateEmail bool

// Apple returns an is_private_email field that could be a string or boolean value so we need to implement a custom unmarshaler
// https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_rest_api/authenticating_users_with_sign_in_with_apple
func (b *IsPrivateEmail) UnmarshalJSON(data []byte) error {
	var boolVal bool
	if err := json.Unmarshal(data, &boolVal); err == nil {
		*b = IsPrivateEmail(boolVal)
		return nil
	}

	// ignore the error and try to unmarshal as a string
	var strVal string
	if err := json.Unmarshal(data, &strVal); err != nil {
		return err
	}

	var err error
	boolVal, err = strconv.ParseBool(strVal)
	if err != nil {
		return err
	}

	*b = IsPrivateEmail(boolVal)
	return nil
}

type appleName struct {
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
}

type appleUser struct {
	Name  appleName `json:"name"`
	Email string    `json:"email"`
}

// NewAppleProvider creates a Apple account provider.
func NewAppleProvider(ctx context.Context, ext conf.OAuthProviderConfiguration) (OAuthProvider, error) {
	if err := ext.ValidateOAuth(); err != nil {
		return nil, err
	}

	if ext.URL != "" {
		logrus.Warn("Apple OAuth provider has URL config set which is ignored (check GOTRUE_EXTERNAL_APPLE_URL)")
	}

	oidcProvider, err := oidc.NewProvider(ctx, IssuerApple)
	if err != nil {
		return nil, err
	}

	return &AppleProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID[0],
			ClientSecret: ext.Secret,
			Endpoint:     oidcProvider.Endpoint(),
			Scopes: []string{
				"email",
				"name",
			},
			RedirectURL: ext.RedirectURI,
		},
		oidc: oidcProvider,
	}, nil
}

// GetOAuthToken returns the apple provider access token
func (p AppleProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("client_id", p.ClientID),
		oauth2.SetAuthURLParam("secret", p.ClientSecret),
	}
	return p.Exchange(context.Background(), code, opts...)
}

func (p AppleProvider) AuthCodeURL(state string, args ...oauth2.AuthCodeOption) string {
	opts := make([]oauth2.AuthCodeOption, 0, 1)
	opts = append(opts, oauth2.SetAuthURLParam("response_mode", "form_post"))
	authURL := p.Config.AuthCodeURL(state, opts...)
	if authURL != "" {
		if u, err := url.Parse(authURL); err != nil {
			u.RawQuery = strings.ReplaceAll(u.RawQuery, "+", "%20")
			authURL = u.String()
		}
	}
	return authURL
}

// GetUserData returns the user data fetched from the apple provider
func (p AppleProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	idToken := tok.Extra("id_token")
	if tok.AccessToken == "" || idToken == nil {
		// Apple returns user data only the first time
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

// ParseUser parses the apple user's info
func (p AppleProvider) ParseUser(data string, userData *UserProvidedData) error {
	u := &appleUser{}
	err := json.Unmarshal([]byte(data), u)
	if err != nil {
		return err
	}

	userData.Metadata.Name = strings.TrimSpace(u.Name.FirstName + " " + u.Name.LastName)
	userData.Metadata.FullName = strings.TrimSpace(u.Name.FirstName + " " + u.Name.LastName)
	return nil
}
