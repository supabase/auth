package provider

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/golang-jwt/jwt"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/netlify/gotrue/conf"
	"golang.org/x/oauth2"
)

const (
	defaultAppleAPIBase = "appleid.apple.com"
	authEndpoint        = "/auth/authorize"
	tokenEndpoint       = "/auth/token"

	scopeEmail = "email"
	scopeName  = "name"

	appleAudOrIss                  = "https://appleid.apple.com"
	idTokenVerificationKeyEndpoint = "/auth/keys"
)

// AppleProvider stores the custom config for apple provider
type AppleProvider struct {
	*oauth2.Config
	UserInfoURL string
}

type appleName struct {
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
}

type appleUser struct {
	Name  appleName `json:"name"`
	Email string    `json:"email"`
}

type idTokenClaims struct {
	jwt.StandardClaims
	AccessTokenHash string `json:"at_hash"`
	AuthTime        int    `json:"auth_time"`
	Email           string `json:"email"`
	IsPrivateEmail  bool   `json:"is_private_email,string"`
	Sub             string `json:"sub"`
}

// NewAppleProvider creates a Apple account provider.
func NewAppleProvider(ext conf.OAuthProviderConfiguration) (OAuthProvider, error) {
	if err := ext.Validate(); err != nil {
		return nil, err
	}

	authHost := chooseHost(ext.URL, defaultAppleAPIBase)

	return &AppleProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID,
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authHost + authEndpoint,
				TokenURL: authHost + tokenEndpoint,
			},
			Scopes: []string{
				scopeEmail,
				scopeName,
			},
			RedirectURL: ext.RedirectURI,
		},
		UserInfoURL: authHost + idTokenVerificationKeyEndpoint,
	}, nil
}

// GetOAuthToken returns the apple provider access token
func (p AppleProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("client_id", p.ClientID),
		oauth2.SetAuthURLParam("secret", p.ClientSecret),
	}
	return p.Exchange(oauth2.NoContext, code, opts...)
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
	var user *UserProvidedData
	if tok.AccessToken == "" {
		return &UserProvidedData{}, nil
	}
	if idToken := tok.Extra("id_token"); idToken != nil {
		idToken, err := jwt.ParseWithClaims(idToken.(string), &idTokenClaims{}, func(t *jwt.Token) (interface{}, error) {
			kid := t.Header["kid"].(string)
			claims := t.Claims.(*idTokenClaims)
			vErr := new(jwt.ValidationError)
			if !claims.VerifyAudience(p.ClientID, true) {
				vErr.Inner = fmt.Errorf("incorrect audience")
				vErr.Errors |= jwt.ValidationErrorAudience
			}
			if !claims.VerifyIssuer(appleAudOrIss, true) {
				vErr.Inner = fmt.Errorf("incorrect issuer")
				vErr.Errors |= jwt.ValidationErrorIssuer
			}
			if vErr.Errors > 0 {
				return nil, vErr
			}

			// per OpenID Connect Core 1.0 §3.2.2.9, Access Token Validation
			hash := sha256.Sum256([]byte(tok.AccessToken))
			halfHash := hash[0:(len(hash) / 2)]
			encodedHalfHash := base64.RawURLEncoding.EncodeToString(halfHash)
			if encodedHalfHash != claims.AccessTokenHash {
				vErr.Inner = fmt.Errorf(`invalid identity token`)
				vErr.Errors |= jwt.ValidationErrorClaimsInvalid
				return nil, vErr
			}

			// get the public key for verifying the identity token signature
			set, err := jwk.FetchHTTP(p.UserInfoURL, jwk.WithHTTPClient(http.DefaultClient))
			if err != nil {
				return nil, err
			}
			selectedKey := set.Keys[0]
			for _, key := range set.Keys {
				if key.KeyID() == kid {
					selectedKey = key
					break
				}
			}
			pubKeyIface, _ := selectedKey.Materialize()
			pubKey, ok := pubKeyIface.(*rsa.PublicKey)
			if !ok {
				return nil, fmt.Errorf(`expected RSA public key from %s`, p.UserInfoURL)
			}
			return pubKey, nil
		})
		if err != nil {
			return &UserProvidedData{}, err
		}
		user = &UserProvidedData{
			Emails: []Email{{
				Email:    idToken.Claims.(*idTokenClaims).Email,
				Verified: true,
				Primary:  true,
			}},
			Metadata: &Claims{
				Issuer:        p.UserInfoURL,
				Subject:       idToken.Claims.(*idTokenClaims).Sub,
				Email:         idToken.Claims.(*idTokenClaims).Email,
				EmailVerified: true,

				// To be deprecated
				ProviderId: idToken.Claims.(*idTokenClaims).Sub,
			},
		}
	}
	return user, nil
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
