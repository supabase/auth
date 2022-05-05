package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/netlify/gotrue/conf"
	"golang.org/x/oauth2"
)

// Twitch

const (
	defaultTwitchAuthBase = "id.twitch.tv"
	defaultTwitchAPIBase  = "api.twitch.tv"
)

type twitchProvider struct {
	*oauth2.Config
	APIHost string
}

type twitchUsers struct {
	Data []struct {
		ID              string    `json:"id"`
		Login           string    `json:"login"`
		DisplayName     string    `json:"display_name"`
		Type            string    `json:"type"`
		BroadcasterType string    `json:"broadcaster_type"`
		Description     string    `json:"description"`
		ProfileImageURL string    `json:"profile_image_url"`
		OfflineImageURL string    `json:"offline_image_url"`
		ViewCount       int       `json:"view_count"`
		Email           string    `json:"email"`
		CreatedAt       time.Time `json:"created_at"`
	} `json:"data"`
}

// NewTwitchProvider creates a Twitch account provider.
func NewTwitchProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.Validate(); err != nil {
		return nil, err
	}

	apiHost := chooseHost(ext.URL, defaultTwitchAPIBase)
	authHost := chooseHost(ext.URL, defaultTwitchAuthBase)

	oauthScopes := []string{
		"user:read:email",
	}

	if scopes != "" {
		oauthScopes = append(oauthScopes, strings.Split(scopes, ",")...)
	}

	return &twitchProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID,
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authHost + "/oauth2/authorize",
				TokenURL: authHost + "/oauth2/token",
			},
			RedirectURL: ext.RedirectURI,
			Scopes:      oauthScopes,
		},
		APIHost: apiHost,
	}, nil
}

func (t twitchProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return t.Exchange(context.Background(), code)
}

func (t twitchProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	var u twitchUsers

	// Perform http request, because we neeed to set the Client-Id header
	req, err := http.NewRequest("GET", t.APIHost+"/helix/users", nil)

	if err != nil {
		return nil, err
	}

	// set headers
	req.Header.Set("Client-Id", t.Config.ClientID)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)

	client := &http.Client{Timeout: defaultTimeout}
	resp, err := client.Do(req)

	if err != nil {
		return nil, err
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("a %v error occurred with retrieving user from twitch", resp.StatusCode)
	}

	body, _ := ioutil.ReadAll(resp.Body)
	json.Unmarshal(body, &u)
	defer resp.Body.Close()

	if len(u.Data) == 0 {
		return nil, errors.New("unable to find user with twitch provider")
	}

	user := u.Data[0]

	if user.Email == "" {
		return nil, errors.New("unable to find email with twitch provider")
	}

	data := &UserProvidedData{
		Metadata: &Claims{
			Issuer:        t.APIHost,
			Subject:       user.ID,
			Picture:       user.ProfileImageURL,
			Name:          user.Login,
			NickName:      user.DisplayName,
			Email:         user.Email,
			EmailVerified: true,
			CustomClaims: map[string]interface{}{
				"broadcaster_type":  user.BroadcasterType,
				"description":       user.Description,
				"type":              user.Type,
				"offline_image_url": user.OfflineImageURL,
				"view_count":        user.ViewCount,
			},

			// To be deprecated
			Slug:       user.DisplayName,
			AvatarURL:  user.ProfileImageURL,
			FullName:   user.Login,
			ProviderId: user.ID,
		},
		Emails: []Email{{
			Email:    user.Email,
			Verified: true,
			Primary:  true,
		}},
	}

	return data, nil
}
