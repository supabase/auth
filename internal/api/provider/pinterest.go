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
	defaultPinterestApiBase = "https://api.pinterest.com"
	pinterestApiVersion     = "v5"
)

type pinterestProvider struct {
	*oauth2.Config
	APIPath string
}

type pinterestUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Profile  struct {
		FullName string `json:"full_name"`
		Email    string `json:"email"`
		Image    string `json:"image"`
	} `json:"profile"`
}

// NewPinterestProvider creates a Pinterest account provider.
func NewPinterestProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.ValidateOAuth(); err != nil {
		return nil, err
	}

	authHost := chooseHost(ext.URL, defaultPinterestApiBase)

	return &pinterestProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID[0],
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authHost + "/" + pinterestApiVersion + "/oauth",
				TokenURL: authHost + "/" + pinterestApiVersion + "/oauth/token",
			},
			RedirectURL: ext.RedirectURI,
		},
		APIPath: authHost,
	}, nil
}

func (p pinterestProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return p.Exchange(context.Background(), code)
}

func (p pinterestProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	var u pinterestUser

	req, err := http.NewRequest("GET", p.APIPath+"/"+pinterestApiVersion+"/user_account", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)

	client := &http.Client{Timeout: defaultTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer utilities.SafeClose(resp.Body)

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("a %v error occurred with retrieving user from Pinterest", resp.StatusCode)
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
	if u.Profile.Email != "" {
		data.Emails = []Email{{
			Email:    u.Profile.Email,
			Verified: true, // Assuming Pinterest verifies emails
			Primary:  true,
		}}
	}

	data.Metadata = &Claims{
		Issuer:  p.APIPath,
		Subject: u.ID,
		Name:    u.Profile.FullName,
		Picture: u.Profile.Image,

		// To be deprecated
		AvatarURL:  u.Profile.Image,
		FullName:   u.Profile.FullName,
		ProviderId: u.ID,
	}
	return data, nil
}
