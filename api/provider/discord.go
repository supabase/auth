package provider

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/netlify/gotrue/conf"
	"golang.org/x/oauth2"
)

const (
	defaultDiscordAPIBase = "discord.com"
)

type discordProvider struct {
	*oauth2.Config
	APIPath string
}

type discordUser struct {
	Avatar        string `json:"avatar"`
	Discriminator string `json:"discriminator"`
	Email         string `json:"email"`
	ID            string `json:"id"`
	Name          string `json:"username"`
	Verified      bool   `json:"verified"`
}

// NewDiscordProvider creates a Discord account provider.
func NewDiscordProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.Validate(); err != nil {
		return nil, err
	}

	apiPath := chooseHost(ext.URL, defaultDiscordAPIBase) + "/api"

	oauthScopes := []string{
		"email",
		"identify",
	}

	if scopes != "" {
		oauthScopes = append(oauthScopes, strings.Split(scopes, ",")...)
	}

	return &discordProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID,
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  apiPath + "/oauth2/authorize",
				TokenURL: apiPath + "/oauth2/token",
			},
			Scopes:      oauthScopes,
			RedirectURL: ext.RedirectURI,
		},
		APIPath: apiPath,
	}, nil
}

func (g discordProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return g.Exchange(oauth2.NoContext, code)
}

func (g discordProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	var u discordUser
	if err := makeRequest(ctx, tok, g.Config, g.APIPath+"/users/@me", &u); err != nil {
		return nil, err
	}

	if u.Email == "" {
		return nil, errors.New("Unable to find email with Discord provider")
	}

	var avatarURL string
	extension := "png"
	if u.Avatar == "" {
		if intDiscriminator, err := strconv.Atoi(u.Discriminator); err != nil {
			return nil, err
		} else {
			// https://discord.com/developers/docs/reference#image-formatting-cdn-endpoints:
			// In the case of the Default User Avatar endpoint, the value for
			// user_discriminator in the path should be the user's discriminator modulo 5
			avatarURL = fmt.Sprintf("https://cdn.discordapp.com/embed/avatars/%d.%s", intDiscriminator%5, extension)
		}
	} else {
		// https://discord.com/developers/docs/reference#image-formatting:
		// "In the case of endpoints that support GIFs, the hash will begin with a_
		// if it is available in GIF format."
		if strings.HasPrefix(u.Avatar, "a_") {
			extension = "gif"
		}
		avatarURL = fmt.Sprintf("https://cdn.discordapp.com/avatars/%s/%s.%s", u.ID, u.Avatar, extension)
	}

	return &UserProvidedData{
		Metadata: &Claims{
			Issuer:        g.APIPath,
			Subject:       u.ID,
			Name:          fmt.Sprintf("%v#%v", u.Name, u.Discriminator),
			Picture:       avatarURL,
			Email:         u.Email,
			EmailVerified: u.Verified,

			// To be deprecated
			AvatarURL:  avatarURL,
			FullName:   u.Name,
			ProviderId: u.ID,
		},
		Emails: []Email{{
			Email:    u.Email,
			Verified: u.Verified,
			Primary:  true,
		}},
	}, nil
}
