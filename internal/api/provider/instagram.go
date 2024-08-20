package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/utilities"
	"golang.org/x/oauth2"
)

const (
	defaultInstagramApiBase = "https://graph.instagram.com"
)

type instagramUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email,omitempty"`
	Picture  string `json:"profile_picture,omitempty"`
}

func NewInstagramProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.ValidateOAuth(); err != nil {
		return nil, err
	}

	authHost := chooseHost(ext.URL, defaultInstagramApiBase)

	return &instagramProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID[0],
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://api.instagram.com/oauth/authorize",
				TokenURL: "https://api.instagram.com/oauth/access_token",
			},
			RedirectURL: ext.RedirectURI,
			Scopes:      []string{"user_profile", "user_media"},
		},
		APIPath: authHost,
	}, nil
}

type instagramProvider struct {
	*oauth2.Config
	APIPath string
}

func (g instagramProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return g.Exchange(context.Background(), code)
}

func (g instagramProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	var u instagramUser

	req, err := http.NewRequest("GET", g.APIPath+"/me?fields=id,username,email,profile_picture&access_token="+tok.AccessToken, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: defaultTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer utilities.SafeClose(resp.Body)

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("a %v error occurred while retrieving user from Instagram", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(body, &u)
	if err != nil {
		return nil, err
	}

	data := &UserProvidedData{}
	if u.Email != "" {
		data.Emails = []Email{{
			Email:    u.Email,
			Verified: true,
			Primary:  true,
		}}
	}

	data.Metadata = &Claims{
		Issuer:  g.APIPath,
		Subject: u.ID,
		Name:    u.Username,
		Picture: u.Picture,

		// To be deprecated
		AvatarURL:  u.Picture,
		FullName:   u.Username,
		ProviderId: u.ID,
	}
	return data, nil
}
