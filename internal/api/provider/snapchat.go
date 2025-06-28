package provider

import (
	"context"
	"net/url"
	"strings"

	"github.com/supabase/auth/internal/conf"
	"golang.org/x/oauth2"
)

const IssuerSnapchat = "https://accounts.snapchat.com"

const (
	defaultSnapchatAuthBase  = "accounts.snapchat.com"
	defaultSnapchatTokenBase = "accounts.snapchat.com"
	defaultSnapchatAPIBase   = "kit.snapchat.com"
)

type snapchatProvider struct {
	*oauth2.Config
	ProfileURL string
}

type snapchatUser struct {
	Data struct {
		Me struct {
			ExternalID  string `json:"externalId"`
			DisplayName string `json:"displayName"`
			Bitmoji     struct {
				Avatar string `json:"avatar"`
			} `json:"bitmoji"`
		} `json:"me"`
	} `json:"data"`
}

// NewSnapchatProvider creates a Snapchat account provider.
func NewSnapchatProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.ValidateOAuth(); err != nil {
		return nil, err
	}

	authHost := chooseHost(ext.URL, defaultSnapchatAuthBase)
	tokenHost := chooseHost(ext.URL, defaultSnapchatTokenBase)
	profileURL := chooseHost(ext.URL, defaultSnapchatAPIBase) + "/v1/me"

	oauthScopes := []string{
		"https://auth.snapchat.com/oauth2/api/user.external_id",
		"https://auth.snapchat.com/oauth2/api/user.display_name",
		"https://auth.snapchat.com/oauth2/api/user.bitmoji.avatar",
	}

	if scopes != "" {
		oauthScopes = append(oauthScopes, strings.Split(scopes, ",")...)
	}

	return &snapchatProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID[0],
			ClientSecret: ext.Secret,
			RedirectURL:  ext.RedirectURI,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authHost + "/accounts/oauth2/auth",
				TokenURL: tokenHost + "/accounts/oauth2/token",
			},
			Scopes: oauthScopes,
		},
		ProfileURL: profileURL,
	}, nil
}

func (p snapchatProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return p.Exchange(context.Background(), code)
}

func (p snapchatProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	var u snapchatUser

	// Create a URL with the GraphQL query parameter
	baseURL, err := url.Parse(p.ProfileURL)
	if err != nil {
		return nil, err
	}

	// Add the GraphQL query parameter
	query := url.Values{}
	query.Add("query", "{me { externalId displayName bitmoji { avatar id } } }")
	baseURL.RawQuery = query.Encode()

	if err := makeRequest(ctx, tok, p.Config, baseURL.String(), &u); err != nil {
		return nil, err
	}

	data := &UserProvidedData{}

	// Snapchat doesn't provide email by default, additional scopes needed
	data.Emails = []Email{{
		Email:    strings.ToLower(u.Data.Me.ExternalID) + "@snapchat.id", // TODO: Create a pseudo-email using the external ID
		Verified: true,
		Primary:  true,
	}}

	data.Metadata = &Claims{
		Issuer:  IssuerSnapchat,
		Subject: u.Data.Me.ExternalID,
		Name:    u.Data.Me.DisplayName,
		Picture: u.Data.Me.Bitmoji.Avatar,

		// To be deprecated
		Slug:       u.Data.Me.DisplayName,
		AvatarURL:  u.Data.Me.Bitmoji.Avatar,
		FullName:   u.Data.Me.DisplayName,
		ProviderId: u.Data.Me.ExternalID,
	}

	return data, nil
}
