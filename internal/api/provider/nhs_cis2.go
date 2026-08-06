package provider

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/supabase/auth/internal/conf"
	"golang.org/x/oauth2"
)

const (
	defaultNHSCIS2Host = "am.nhsidentity.spineservices.nhs.uk"
	// NHS CIS2 OIDC paths
	nhsCIS2AuthPath     = "/openam/oauth2/realms/root/realms/NHSIdentity/realms/Healthcare/authorize"
	nhsCIS2TokenPath    = "/openam/oauth2/realms/root/realms/NHSIdentity/realms/Healthcare/access_token"
	nhsCIS2UserInfoPath = "/openam/oauth2/realms/root/realms/NHSIdentity/realms/Healthcare/userinfo"
)

// nhsCIS2Provider implements the OAuthProvider interface for NHS Care Identity Service 2 (CIS2)
type nhsCIS2Provider struct {
	*oauth2.Config
	Host string
}

// nhsCIS2User represents the user data returned from NHS CIS2 userinfo endpoint
type nhsCIS2User struct {
	Sub                    string                 `json:"sub"`
	Email                  string                 `json:"email"`
	EmailVerified          bool                   `json:"email_verified"`
	Name                   string                 `json:"name"`
	GivenName              string                 `json:"given_name"`
	FamilyName             string                 `json:"family_name"`
	PreferredUsername      string                 `json:"preferred_username"`
	UID                    string                 `json:"uid"`
	NHSNumber              string                 `json:"nhsid_nrbac_roles,omitempty"`
	IDAssuranceLevel       string                 `json:"id_assurance_level,omitempty"`
	AuthenticationLevel    string                 `json:"authentication_assurance_level,omitempty"`
	OrganizationCode       string                 `json:"selected_roleid,omitempty"`
	RawClaims              map[string]interface{} `json:"-"`
}

func (u *nhsCIS2User) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &u.RawClaims); err != nil {
		return err
	}

	// Extract known fields
	if v, ok := u.RawClaims["sub"].(string); ok {
		u.Sub = v
	}
	if v, ok := u.RawClaims["email"].(string); ok {
		u.Email = v
	}
	if v, ok := u.RawClaims["email_verified"].(bool); ok {
		u.EmailVerified = v
	}
	if v, ok := u.RawClaims["name"].(string); ok {
		u.Name = v
	}
	if v, ok := u.RawClaims["given_name"].(string); ok {
		u.GivenName = v
	}
	if v, ok := u.RawClaims["family_name"].(string); ok {
		u.FamilyName = v
	}
	if v, ok := u.RawClaims["preferred_username"].(string); ok {
		u.PreferredUsername = v
	}
	if v, ok := u.RawClaims["uid"].(string); ok {
		u.UID = v
	}
	if v, ok := u.RawClaims["nhsid_nrbac_roles"].(string); ok {
		u.NHSNumber = v
	}
	if v, ok := u.RawClaims["id_assurance_level"].(string); ok {
		u.IDAssuranceLevel = v
	}
	if v, ok := u.RawClaims["authentication_assurance_level"].(string); ok {
		u.AuthenticationLevel = v
	}
	if v, ok := u.RawClaims["selected_roleid"].(string); ok {
		u.OrganizationCode = v
	}

	return nil
}

// NewNHSCIS2Provider creates a new NHS CIS2 OAuth provider
func NewNHSCIS2Provider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
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

	host := chooseHost(ext.URL, defaultNHSCIS2Host)

	return &nhsCIS2Provider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID[0],
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  host + nhsCIS2AuthPath,
				TokenURL: host + nhsCIS2TokenPath,
			},
			RedirectURL: ext.RedirectURI,
			Scopes:      oauthScopes,
		},
		Host: host,
	}, nil
}

// GetOAuthToken exchanges an authorization code for an OAuth token
func (p nhsCIS2Provider) GetOAuthToken(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	return p.Exchange(ctx, code, opts...)
}

// RequiresPKCE returns whether this provider requires PKCE
func (p nhsCIS2Provider) RequiresPKCE() bool {
	return false
}

// GetUserData fetches user data from the NHS CIS2 userinfo endpoint
func (p nhsCIS2Provider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	var u nhsCIS2User

	if err := makeRequest(ctx, tok, p.Config, p.Host+nhsCIS2UserInfoPath, &u); err != nil {
		return nil, err
	}

	data := &UserProvidedData{}

	if u.Email != "" {
		data.Emails = []Email{{
			Email:    u.Email,
			Verified: u.EmailVerified,
			Primary:  true,
		}}
	}

	// Build custom claims from NHS-specific data
	customClaims := make(map[string]interface{})
	standardClaims := map[string]bool{
		"sub": true, "email": true, "email_verified": true,
		"name": true, "given_name": true, "family_name": true,
		"preferred_username": true,
	}

	for k, v := range u.RawClaims {
		if !standardClaims[k] {
			customClaims[k] = v
		}
	}

	// Construct full name if not provided
	fullName := u.Name
	if fullName == "" && (u.GivenName != "" || u.FamilyName != "") {
		fullName = strings.TrimSpace(u.GivenName + " " + u.FamilyName)
	}

	data.Metadata = &Claims{
		Issuer:            p.Host,
		Subject:           u.Sub,
		Name:              fullName,
		GivenName:         u.GivenName,
		FamilyName:        u.FamilyName,
		PreferredUsername: u.PreferredUsername,
		Email:             u.Email,
		EmailVerified:     u.EmailVerified,
		CustomClaims:      customClaims,

		// To be deprecated
		FullName:   fullName,
		ProviderId: u.Sub,
	}

	return data, nil
}
