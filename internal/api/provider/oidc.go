package provider

import (
	"context"
	"errors"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt"
)

type ParseIDTokenOptions struct {
	SkipAccessTokenCheck bool
	AccessToken          string
}

// OverrideVerifiers can be used to set a custom verifier for an OIDC provider
// (identified by the provider's Endpoint().AuthURL string). Should only be
// used in tests.
var OverrideVerifiers = make(map[string]func(context.Context, *oidc.Config) *oidc.IDTokenVerifier)

func ParseIDToken(ctx context.Context, provider *oidc.Provider, config *oidc.Config, idToken string, options ParseIDTokenOptions) (*oidc.IDToken, *UserProvidedData, error) {
	if config == nil {
		config = &oidc.Config{
			// aud claim check to be performed by other flows
			SkipClientIDCheck: true,
		}
	}

	verifier := provider.VerifierContext(ctx, config)
	overrideVerifier, ok := OverrideVerifiers[provider.Endpoint().AuthURL]
	if ok && overrideVerifier != nil {
		verifier = overrideVerifier(ctx, config)
	}

	token, err := verifier.Verify(ctx, idToken)
	if err != nil {
		return nil, nil, err
	}

	var data *UserProvidedData

	switch token.Issuer {
	case IssuerGoogle:
		token, data, err = parseGoogleIDToken(token)

	case IssuerApple:
		token, data, err = parseAppleIDToken(token)

	default:
		token, data, err = parseGenericIDToken(token)
	}

	if err != nil {
		return nil, nil, err
	}

	if !options.SkipAccessTokenCheck && token.AccessTokenHash != "" {
		if err := token.VerifyAccessToken(options.AccessToken); err != nil {
			return nil, nil, err
		}
	}

	return token, data, nil
}

func parseGoogleIDToken(token *oidc.IDToken) (*oidc.IDToken, *UserProvidedData, error) {
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

type AppleIDTokenClaims struct {
	jwt.StandardClaims

	Email string `json:"email"`

	AuthTime       *float64 `json:"auth_time"`
	IsPrivateEmail *bool    `json:"is_private_email,string"`
}

func parseAppleIDToken(token *oidc.IDToken) (*oidc.IDToken, *UserProvidedData, error) {
	var claims AppleIDTokenClaims
	if err := token.Claims(&claims); err != nil {
		return nil, nil, err
	}

	var data UserProvidedData

	data.Emails = append(data.Emails, Email{
		Email:    claims.Email,
		Verified: true,
		Primary:  true,
	})

	data.Metadata = &Claims{
		Issuer:        token.Issuer,
		Subject:       token.Subject,
		Email:         claims.Email,
		EmailVerified: true,
		ProviderId:    token.Subject,
		CustomClaims:  make(map[string]any),
	}

	if claims.IsPrivateEmail != nil {
		data.Metadata.CustomClaims["is_private_email"] = *claims.IsPrivateEmail
	}

	if claims.AuthTime != nil {
		data.Metadata.CustomClaims["auth_time"] = *claims.AuthTime
	}

	if len(data.Metadata.CustomClaims) < 1 {
		data.Metadata.CustomClaims = nil
	}

	return token, &data, nil
}

func parseGenericIDToken(token *oidc.IDToken) (*oidc.IDToken, *UserProvidedData, error) {
	var data UserProvidedData

	if err := token.Claims(&data.Metadata); err != nil {
		return nil, nil, err
	}

	if data.Metadata.Email != "" {
		data.Emails = append(data.Emails, Email{
			Email:    data.Metadata.Email,
			Verified: data.Metadata.EmailVerified,
			Primary:  true,
		})
	}

	if len(data.Emails) <= 0 {
		return nil, nil, fmt.Errorf("provider: Generic OIDC ID token from issuer %q must contain an email address", token.Issuer)
	}

	return token, &data, nil
}
