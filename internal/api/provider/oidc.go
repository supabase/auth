package provider

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

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

// OverrideClock can be used to set a custom clock function to be used when
// parsing ID tokens. Should only be used in tests.
var OverrideClock func() time.Time

func ParseIDToken(ctx context.Context, provider *oidc.Provider, config *oidc.Config, idToken string, options ParseIDTokenOptions) (*oidc.IDToken, *UserProvidedData, error) {
	if config == nil {
		config = &oidc.Config{
			// aud claim check to be performed by other flows
			SkipClientIDCheck: true,
		}
	}

	if OverrideClock != nil {
		clonedConfig := *config
		clonedConfig.Now = OverrideClock
		config = &clonedConfig
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
	case IssuerLinkedin:
		token, data, err = parseLinkedinIDToken(token)
	default:
		if IsAzureIssuer(token.Issuer) {
			token, data, err = parseAzureIDToken(token)
		} else {
			token, data, err = parseGenericIDToken(token)
		}
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

	data.Metadata = &Claims{
		Issuer:  claims.Issuer,
		Subject: claims.Subject,
		Name:    claims.Name,
		Picture: claims.AvatarURL,

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
		Issuer:       token.Issuer,
		Subject:      token.Subject,
		ProviderId:   token.Subject,
		CustomClaims: make(map[string]any),
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

type LinkedinIDTokenClaims struct {
	jwt.StandardClaims

	Email         string `json:"email"`
	EmailVerified string `json:"email_verified"`
	FamilyName    string `json:"family_name"`
	GivenName     string `json:"given_name"`
	Locale        string `json:"locale"`
	Picture       string `json:"picture"`
}

func parseLinkedinIDToken(token *oidc.IDToken) (*oidc.IDToken, *UserProvidedData, error) {
	var claims LinkedinIDTokenClaims
	if err := token.Claims(&claims); err != nil {
		return nil, nil, err
	}

	var data UserProvidedData
	emailVerified, err := strconv.ParseBool(claims.EmailVerified)
	if err != nil {
		return nil, nil, err
	}

	if claims.Email != "" {
		data.Emails = append(data.Emails, Email{
			Email:    claims.Email,
			Verified: emailVerified,
			Primary:  true,
		})
	}

	data.Metadata = &Claims{
		Issuer:     token.Issuer,
		Subject:    token.Subject,
		Name:       strings.TrimSpace(claims.GivenName + " " + claims.FamilyName),
		GivenName:  claims.GivenName,
		FamilyName: claims.FamilyName,
		Locale:     claims.Locale,
		Picture:    claims.Picture,
		ProviderId: token.Subject,
	}

	return token, &data, nil
}

type AzureIDTokenClaims struct {
	jwt.StandardClaims

	Email                              string `json:"email"`
	Name                               string `json:"name"`
	PreferredUsername                  string `json:"preferred_username"`
	XMicrosoftEmailDomainOwnerVerified any    `json:"xms_edov"`
}

func (c *AzureIDTokenClaims) IsEmailVerified() bool {
	emailVerified := false

	edov := c.XMicrosoftEmailDomainOwnerVerified

	// If xms_edov is not set, and an email is present or xms_edov is true,
	// only then is the email regarded as verified.
	// https://learn.microsoft.com/en-us/azure/active-directory/develop/migrate-off-email-claim-authorization#using-the-xms_edov-optional-claim-to-determine-email-verification-status-and-migrate-users
	if edov == nil {
		// An email is provided, but xms_edov is not -- probably not
		// configured, so we must assume the email is verified as Azure
		// will only send out a potentially unverified email address in
		// single-tenanat apps.
		emailVerified = c.Email != ""
	} else {
		edovBool := false

		// Azure can't be trusted with how they encode the xms_edov
		// claim. Sometimes it's "xms_edov": "1", sometimes "xms_edov": true.
		switch v := edov.(type) {
		case bool:
			edovBool = v

		case string:
			edovBool = v == "1" || v == "true"

		default:
			edovBool = false
		}

		emailVerified = c.Email != "" && edovBool
	}

	return emailVerified
}

// removeAzureClaimsFromCustomClaims contains the list of claims to be removed
// from the CustomClaims map. See:
// https://learn.microsoft.com/en-us/azure/active-directory/develop/id-token-claims-reference
var removeAzureClaimsFromCustomClaims = []string{
	"aud",
	"iss",
	"iat",
	"nbf",
	"exp",
	"c_hash",
	"at_hash",
	"aio",
	"nonce",
	"rh",
	"uti",
	"jti",
	"ver",
	"sub",
	"name",
	"preferred_username",
}

func parseAzureIDToken(token *oidc.IDToken) (*oidc.IDToken, *UserProvidedData, error) {
	var data UserProvidedData

	var azureClaims AzureIDTokenClaims
	if err := token.Claims(&azureClaims); err != nil {
		return nil, nil, err
	}

	data.Metadata = &Claims{
		Issuer:            token.Issuer,
		Subject:           token.Subject,
		ProviderId:        token.Subject,
		PreferredUsername: azureClaims.PreferredUsername,
		FullName:          azureClaims.Name,
		CustomClaims:      make(map[string]any),
	}

	if azureClaims.Email != "" {
		data.Emails = []Email{{
			Email:    azureClaims.Email,
			Verified: azureClaims.IsEmailVerified(),
			Primary:  true,
		}}
	}

	if err := token.Claims(&data.Metadata.CustomClaims); err != nil {
		return nil, nil, err
	}

	if data.Metadata.CustomClaims != nil {
		for _, claim := range removeAzureClaimsFromCustomClaims {
			delete(data.Metadata.CustomClaims, claim)
		}
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
