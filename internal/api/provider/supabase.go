package provider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/supabase/auth/internal/conf"
	"golang.org/x/oauth2"
)

// SupabaseProvider represents a Supabase OAuth provider
type SupabaseProvider struct {
	*oauth2.Config
}

// NewSupabaseProvider creates a Supabase OAuth2 provider.
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

	// Supabase Auth OAuth endpoints
	// TODO(cemal) :: update to use oidc.NewProvider when supabase auth supports oidc
	authURL := baseURL + "/oauth/authorize"
	tokenURL := baseURL + "/oauth/token"

	return &SupabaseProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID[0],
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authURL,
				TokenURL: tokenURL,
			},
			Scopes:      oauthScopes,
			RedirectURL: ext.RedirectURI,
		},
	}, nil
}

func (p SupabaseProvider) GetOAuthToken(code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	return p.Exchange(context.Background(), code, opts...)
}

func (p SupabaseProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	// TEMP(cemal): Supabase Auth doesn't expose a userinfo endpoint yet.
	// Until then, decode claims from the freshly issued OAuth token without signature verification.

	data := &UserProvidedData{}
	data.Metadata = &Claims{}
	claimsMap, err := decodeJWTClaims(tok.AccessToken)
	if err == nil {
		// Extract email and email_verified from claims
		email, _ := claimsMap["email"].(string)

		// email_verified may live under user_metadata.email_verified
		emailVerified := false
		if uv, ok := claimsMap["email_verified"].(bool); ok {
			emailVerified = uv
		} else if um, ok := claimsMap["user_metadata"].(map[string]interface{}); ok {
			if uv2, ok2 := um["email_verified"].(bool); ok2 {
				emailVerified = uv2
			}
		}

		if email != "" {
			data.Emails = []Email{{
				Email:    email,
				Verified: emailVerified,
				Primary:  true,
			}}
		}

		if iss, ok := claimsMap["iss"].(string); ok {
			data.Metadata.Issuer = iss
		}
		if sub, ok := claimsMap["sub"].(string); ok {
			data.Metadata.Subject = sub
			// To be deprecated
			data.Metadata.ProviderId = sub
		}
		if aud, ok := claimsMap["aud"].(string); ok {
			data.Metadata.Aud = audience{aud}
		}

		data.Metadata.Email = email
		data.Metadata.EmailVerified = emailVerified

		// Carry through app_metadata and user_metadata as custom claims
		customClaims := make(map[string]interface{})
		if am, ok := claimsMap["app_metadata"].(map[string]interface{}); ok && len(am) > 0 {
			customClaims["app_metadata"] = am
		}
		if um, ok := claimsMap["user_metadata"].(map[string]interface{}); ok && len(um) > 0 {
			customClaims["user_metadata"] = um
		}
		if clientId, ok := claimsMap["client_id"].(string); ok {
			customClaims["client_id"] = clientId
		}

		if len(customClaims) > 0 {
			data.Metadata.CustomClaims = customClaims
		}
	}

	return data, nil
}

// RequiresPKCE returns true as Supabase requires PKCE for OAuth
func (p *SupabaseProvider) RequiresPKCE() bool {
	return true
}

// decodeJWTClaims decodes the claims section of a JWT without verifying the signature.
// This is safe here because the token was just issued by authorization code flow.
func decodeJWTClaims(token string) (map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, errors.New("invalid jwt format")
	}
	payloadSegment := parts[1]
	decoded, err := base64.RawURLEncoding.DecodeString(payloadSegment)
	if err != nil {
		return nil, err
	}
	var m map[string]interface{}
	if err := json.Unmarshal(decoded, &m); err != nil {
		return nil, err
	}
	return m, nil
}
