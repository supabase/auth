package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/supabase/auth/internal/conf"
	"golang.org/x/oauth2"
)

const (
	defaultTikTokIssuerURL = "https://www.tiktok.com"
)

type tiktokProvider struct {
	*oauth2.Config
	Client *http.Client
}

type tiktokUser struct {
	ID              string `json:"open_id"`
	UnionID         string `json:"union_id"`
	DisplayName     string `json:"display_name"`
	AvatarUrl       string `json:"avatar_url"`
	AvatarUrlLarge  string `json:"avatar_large_url"`
	ProfileDeepLink string `json:"profile_deep_link"`
	Username        string `json:"username"`
	IsVerified      string `json:"is_verified"`
	FollowerCount   string `json:"follower_count"`
	FollowingCount  string `json:"following_count"`
	LikesCount      string `json:"likes_count"`
	VideoCount      string `json:"video_count"`
}

// NewTikTokProvider creates a TikTok account provider.
func NewTikTokProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.ValidateOAuth(); err != nil {
		return nil, err
	}

	apiPath := chooseHost(ext.URL, defaultTikTokIssuerURL)

	oauthScopes := []string{
		"user.info.basic",
		"video.list",
	}

	if scopes != "" {
		oauthScopes = append(oauthScopes, strings.Split(scopes, ",")...)
	}

	return &tiktokProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID[0],
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  apiPath + "/v2/oauth/authorize/",
				TokenURL: apiPath + "/v2/oauth/token/",
			},
			Scopes:      oauthScopes,
			RedirectURL: ext.RedirectURI,
		},
	}, nil
}

func (t tiktokProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return t.Exchange(context.Background(), code)
}

func (t tiktokProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	var u tiktokUser

	fields := []string{
		"open_id",
		"union_id",
		"display_name",
		"avatar_url",
		"avatar_large_url",
		"profile_deep_link",
		"username",
		"is_verified",
		"follower_count",
		"following_count",
		"likes_count",
		"video_count",
	}
	params := url.Values{}
	params.Add("fields", strings.Join(fields, ","))
	resp, err := t.Config.Client(ctx, tok).Get("https://open.tiktokapis.com/v2/user/info/")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return nil, err
	}

	return &UserProvidedData{
		Metadata: &Claims{
			Issuer:            defaultTikTokIssuerURL,
			Subject:           u.ID,
			Name:              u.DisplayName,
			Picture:           u.AvatarUrl,
			PreferredUsername: u.Username,
			UserNameKey:       u.Username,
			Profile:           u.ProfileDeepLink,
			CustomClaims: map[string]interface{}{
				"is_verified":     u.IsVerified,
				"union_id":        u.UnionID,
				"follower_count":  u.FollowerCount,
				"following_count": u.FollowingCount,
				"likes_count":     u.LikesCount,
				"video_count":     u.VideoCount,
			},

			// To be deprecated
			AvatarURL:  u.AvatarUrl,
			FullName:   u.DisplayName,
			ProviderId: u.ID,
		},
	}, nil
}
