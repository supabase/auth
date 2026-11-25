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
	defaultNotionApiBase = "api.notion.com"
	notionApiVersion     = "2021-08-16"
)

type notionProvider struct {
	*oauth2.Config
	APIPath string
}

type notionUser struct {
	Bot struct {
		Owner struct {
			User struct {
				ID        string `json:"id"`
				Name      string `json:"name"`
				AvatarURL string `json:"avatar_url"`
				Person    struct {
					Email string `json:"email"`
				} `json:"person"`
			} `json:"user"`
		} `json:"owner"`
	} `json:"bot"`
}

// NewNotionProvider creates a Notion account provider.
func NewNotionProvider(ext conf.OAuthProviderConfiguration) (OAuthProvider, error) {
	if err := ext.ValidateOAuth(); err != nil {
		return nil, err
	}

	authHost := chooseHost(ext.URL, defaultNotionApiBase)

	return &notionProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID[0],
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authHost + "/v1/oauth/authorize",
				TokenURL: authHost + "/v1/oauth/token",
			},
			RedirectURL: ext.RedirectURI,
		},
		APIPath: authHost,
	}, nil
}

func (g notionProvider) GetOAuthToken(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	return g.Exchange(ctx, code, opts...)
}

func (g notionProvider) RequiresPKCE() bool {
	return false
}

func (g notionProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	// Notion's token response already includes owner.user. /v1/users/me rejects
	// some OAuth tokens with 403, so prefer the token payload when it is present.
	if u, ok := notionUserFromToken(tok); ok {
		return notionProvidedData(g.APIPath, u), nil
	}

	u, err := g.fetchNotionUser(ctx, tok)
	if err != nil {
		return nil, err
	}
	return notionProvidedData(g.APIPath, u), nil
}

func notionUserFromToken(tok *oauth2.Token) (notionUser, bool) {
	if tok == nil {
		return notionUser{}, false
	}
	owner := tok.Extra("owner")
	if owner == nil {
		return notionUser{}, false
	}
	raw, err := json.Marshal(map[string]any{
		"bot": map[string]any{"owner": owner},
	})
	if err != nil {
		return notionUser{}, false
	}
	var u notionUser
	if err := json.Unmarshal(raw, &u); err != nil {
		return notionUser{}, false
	}
	if u.Bot.Owner.User.ID == "" && u.Bot.Owner.User.Person.Email == "" && u.Bot.Owner.User.Name == "" {
		return notionUser{}, false
	}
	return u, true
}

func (g notionProvider) fetchNotionUser(ctx context.Context, tok *oauth2.Token) (notionUser, error) {
	var u notionUser

	// Perform http request, because we need to set the Notion-Version header
	req, err := http.NewRequestWithContext(ctx, "GET", g.APIPath+"/v1/users/me", nil)
	if err != nil {
		return u, err
	}

	req.Header.Set("Notion-Version", notionApiVersion)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)

	client := &http.Client{Timeout: defaultTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return u, err
	}
	defer utilities.SafeClose(resp.Body)

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return u, fmt.Errorf("a %v error occurred with retrieving user from notion", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return u, err
	}
	if err := json.Unmarshal(body, &u); err != nil {
		return u, err
	}
	return u, nil
}

func notionProvidedData(issuer string, u notionUser) *UserProvidedData {
	data := &UserProvidedData{}
	if u.Bot.Owner.User.Person.Email != "" {
		data.Emails = []Email{{
			Email:    u.Bot.Owner.User.Person.Email,
			Verified: true, // Notion dosen't provide data on if email is verified.
			Primary:  true,
		}}
	}

	data.Metadata = &Claims{
		Issuer:  issuer,
		Subject: u.Bot.Owner.User.ID,
		Name:    u.Bot.Owner.User.Name,
		Picture: u.Bot.Owner.User.AvatarURL,

		// To be deprecated
		AvatarURL:  u.Bot.Owner.User.AvatarURL,
		FullName:   u.Bot.Owner.User.Name,
		ProviderId: u.Bot.Owner.User.ID,
	}
	return data
}
