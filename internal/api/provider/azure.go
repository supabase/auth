package provider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/supabase/auth/internal/conf"
	"golang.org/x/oauth2"
)

const IssuerAzureCommon = "https://login.microsoftonline.com/common/v2.0"
const IssuerAzureOrganizations = "https://login.microsoftonline.com/organizations/v2.0"

// IssuerAzureMicrosoft is the OIDC issuer for microsoft.com accounts:
// https://learn.microsoft.com/en-us/azure/active-directory/develop/id-token-claims-reference#payload-claims
const IssuerAzureMicrosoft = "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0"

const (
	defaultAzureAuthBase = "login.microsoftonline.com/common"
)

type azureProvider struct {
	*oauth2.Config

	// ExpectedIssuer contains the OIDC issuer that should be expected when
	// the authorize flow completes. For example, when using the "common"
	// endpoint the authorization flow will end with an ID token that
	// contains any issuer. In this case, ExpectedIssuer is an empty
	// string, because any issuer is allowed. But if a developer sets up a
	// tenant-specific authorization endpoint, then we must ensure that the
	// ID token received is issued by that specific issuer, and so
	// ExpectedIssuer contains the issuer URL of that tenant.
	ExpectedIssuer string
}

var azureIssuerRegexp = regexp.MustCompile("^https://login[.]microsoftonline[.]com/([^/]+)/v2[.]0/?$")
var azureCIAMIssuerRegexp = regexp.MustCompile("^https://[a-z0-9-]+[.]ciamlogin[.]com/([^/]+)/v2[.]0/?$")

func IsAzureIssuer(issuer string) bool {
	return azureIssuerRegexp.MatchString(issuer)
}

func IsAzureCIAMIssuer(issuer string) bool {
	return azureCIAMIssuerRegexp.MatchString(issuer)
}

// NewAzureProvider creates a Azure account provider.
func NewAzureProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.ValidateOAuth(); err != nil {
		return nil, err
	}

	oauthScopes := []string{"openid"}

	if scopes != "" {
		oauthScopes = append(oauthScopes, strings.Split(scopes, ",")...)
	}

	authHost := chooseHost(ext.URL, defaultAzureAuthBase)
	expectedIssuer := ""

	if ext.URL != "" {
		expectedIssuer = authHost + "/v2.0"

		if !IsAzureIssuer(expectedIssuer) || !IsAzureCIAMIssuer(expectedIssuer) || expectedIssuer == IssuerAzureCommon || expectedIssuer == IssuerAzureOrganizations {
			// in tests, the URL is a local server which should not
			// be the expected issuer
			// also, IssuerAzure (common) never actually issues any
			// ID tokens so it needs to be ignored
			expectedIssuer = ""
		}
	}

	return &azureProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID[0],
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authHost + "/oauth2/v2.0/authorize",
				TokenURL: authHost + "/oauth2/v2.0/token",
			},
			RedirectURL: ext.RedirectURI,
			Scopes:      oauthScopes,
		},
		ExpectedIssuer: expectedIssuer,
	}, nil
}

func (g azureProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return g.Exchange(context.Background(), code)
}

func DetectAzureIDTokenIssuer(ctx context.Context, idToken string) (string, error) {
	var payload struct {
		Issuer string `json:"iss"`
	}

	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("azure: invalid ID token")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("azure: invalid ID token %w", err)
	}

	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return "", fmt.Errorf("azure: invalid ID token %w", err)
	}

	return payload.Issuer, nil
}

func (g azureProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	idToken := tok.Extra("id_token")

	if idToken != nil {
		issuer, err := DetectAzureIDTokenIssuer(ctx, idToken.(string))
		if err != nil {
			return nil, err
		}

		// Allow basic Azure issuers, except when the expected issuer
		// is configured to be the Azure CIAM issuer, allow CIAM
		// issuers to pass.
		if !IsAzureIssuer(issuer) && (IsAzureCIAMIssuer(g.ExpectedIssuer) && !IsAzureCIAMIssuer(issuer)) {
			return nil, fmt.Errorf("azure: ID token issuer not valid %q", issuer)
		}

		if g.ExpectedIssuer != "" && issuer != g.ExpectedIssuer {
			// Since ExpectedIssuer was set, then the developer had
			// setup GoTrue to use the tenant-specific
			// authorization endpoint, which in-turn means that
			// only those tenant's ID tokens will be accepted.
			return nil, fmt.Errorf("azure: ID token issuer %q does not match expected issuer %q", issuer, g.ExpectedIssuer)
		}

		provider, err := oidc.NewProvider(ctx, issuer)
		if err != nil {
			return nil, err
		}

		_, data, err := ParseIDToken(ctx, provider, &oidc.Config{
			ClientID: g.ClientID,
		}, idToken.(string), ParseIDTokenOptions{
			AccessToken: tok.AccessToken,
		})
		if err != nil {
			return nil, err
		}

		return data, nil
	}

	// Only ID tokens supported, UserInfo endpoint has a history of being less secure.

	return nil, fmt.Errorf("azure: no OIDC ID token present in response")
}

type AzureIDTokenClaimSource struct {
	Endpoint string `json:"endpoint"`
}

type AzureIDTokenClaims struct {
	jwt.RegisteredClaims

	Email                              string `json:"email"`
	Name                               string `json:"name"`
	PreferredUsername                  string `json:"preferred_username"`
	XMicrosoftEmailDomainOwnerVerified any    `json:"xms_edov"`

	ClaimNames   map[string]string                  `json:"__claim_names"`
	ClaimSources map[string]AzureIDTokenClaimSource `json:"__claim_sources"`
}

// ResolveIndirectClaims resolves claims in the Azure Token that require a call to the Microsoft Graph API. This is typically to an API like this: https://learn.microsoft.com/en-us/graph/api/directoryobject-getmemberobjects?view=graph-rest-1.0&tabs=http
func (c *AzureIDTokenClaims) ResolveIndirectClaims(ctx context.Context, httpClient *http.Client, accessToken string) (map[string]any, error) {
	if len(c.ClaimNames) == 0 || len(c.ClaimSources) == 0 {
		return nil, nil
	}

	result := make(map[string]any)

	for claimName, claimSource := range c.ClaimNames {
		claimEndpointObject, ok := c.ClaimSources[claimSource]

		if !ok || !strings.HasPrefix(claimEndpointObject.Endpoint, "https://") {
			continue
		}

		claimEndpoint := claimEndpointObject.Endpoint

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, claimEndpoint, strings.NewReader(`{"securityEnabledOnly":true}`))
		if err != nil {
			return nil, fmt.Errorf("azure: failed to create POST request to %q (resolving overage claim %q): %w", claimEndpoint, claimName, err)
		}

		req.Header.Add("Authorization", "Bearer "+accessToken)
		req.Header.Add("Content-Type", "application/json")

		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("azure: failed to send POST request to %q (resolving overage claim %q): %w", claimEndpoint, claimName, err)
		}

		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			resBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 2*1024))

			body := "<empty>"
			if len(resBody) > 0 {
				if utf8.Valid(resBody) {
					body = string(resBody)
				} else {
					body = "<invalid-utf8>"
				}
			}

			readErrString := ""
			if readErr != nil {
				readErrString = fmt.Sprintf(" with read error %q", readErr.Error())
			}

			return nil, fmt.Errorf("azure: received %d but expected 200 HTTP status code when sending POST to %q (resolving overage claim %q) with response body %q%s", resp.StatusCode, claimEndpoint, claimName, body, readErrString)
		}

		var responseResult struct {
			Value any `json:"value"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&responseResult); err != nil {
			return nil, fmt.Errorf("azure: failed to parse JSON response from POST to %q (resolving overage claim %q): %w", claimEndpoint, claimName, err)
		}

		result[claimName] = responseResult.Value
	}

	return result, nil
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

func parseAzureIDToken(ctx context.Context, token *oidc.IDToken, accessToken string) (*oidc.IDToken, *UserProvidedData, error) {
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

	resolvedClaims, err := azureClaims.ResolveIndirectClaims(ctx, http.DefaultClient, accessToken)
	if err != nil {
		return nil, nil, err
	}

	if data.Metadata.CustomClaims == nil {
		if resolvedClaims != nil {
			data.Metadata.CustomClaims = make(map[string]any, len(resolvedClaims))
		}
	}

	if data.Metadata.CustomClaims != nil {
		for _, claim := range removeAzureClaimsFromCustomClaims {
			delete(data.Metadata.CustomClaims, claim)
		}
	}

	for k, v := range resolvedClaims {
		data.Metadata.CustomClaims[k] = v
	}

	return token, &data, nil
}
