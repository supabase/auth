package provider

import (
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"

	"github.com/supabase/auth/internal/conf"
	"golang.org/x/oauth2"
)

// Instagram
type instagramProvider struct {
	*oauth2.Config
}

type instagramUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}

// NewInstagramProvider creates an Instagram account provider.
func NewInstagramProvider(ext conf.OAuthProviderConfiguration) (OAuthProvider, error) {
	if err := ext.ValidateOAuth(); err != nil {
		return nil, err
	}

	return &instagramProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID[0],
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://api.instagram.com/oauth/authorize",
				TokenURL: "https://api.instagram.com/oauth/access_token",
			},
			RedirectURL: ext.RedirectURI,
			Scopes:      []string{"user_profile"},
		},
	}, nil
}

func (g instagramProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return g.Exchange(context.Background(), code)
}

func (g instagramProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	client := g.Client(ctx, tok)
	resp, err := client.Get("https://graph.instagram.com/me?fields=id,username")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var u instagramUser
	if err := json.Unmarshal(body, &u); err != nil {
		return nil, err
	}

	data := &UserProvidedData{
		Metadata: &Claims{
			Issuer:     "https://instagram.com",
			Subject:    u.ID,
			Name:       u.Username,
			ProviderId: u.ID,
		},
	}

	return data, nil
}
