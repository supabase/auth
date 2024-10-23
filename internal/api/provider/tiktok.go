package provider

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/utilities"
	"golang.org/x/oauth2"
)

const (
	defaultTikTokIssuerURL = "https://www.tiktok.com"
)

type tiktokProvider struct {
	*oauth2.Config
	Client *http.Client
}

type tiktokUserResponse struct {
	Data  tiktokUserData  `json:"data"`
	Error tiktokErrorData `json:"error"`
}
type tiktokUserData struct {
	User tiktokUser `json:"user"`
}

type tiktokErrorData struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	LogID   string `json:"log_id"`
}

type tiktokUser struct {
	ID              string `json:"open_id"`
	UnionID         string `json:"union_id"`
	DisplayName     string `json:"display_name"`
	AvatarUrl       string `json:"avatar_url"`
	AvatarUrlLarge  string `json:"avatar_large_url"`
	BioDescription  string `json:"bio_description"`
	ProfileDeepLink string `json:"profile_deep_link"`
	Username        string `json:"username"`
	IsVerified      bool   `json:"is_verified"`
	FollowerCount   int64  `json:"follower_count"`
	FollowingCount  int64  `json:"following_count"`
	LikesCount      int64  `json:"likes_count"`
	VideoCount      int64  `json:"video_count"`
}

// NewTikTokProvider creates a TikTok account provider.
func NewTikTokProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.ValidateOAuth(); err != nil {
		return nil, err
	}

	authorizePath := chooseHost(ext.URL, "www.tiktok.com")
	tokenPath := chooseHost(ext.URL, "open.tiktokapis.com")

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
				AuthURL:  authorizePath + "/v2/auth/authorize/",
				TokenURL: tokenPath + "/v2/oauth/token/",
			},
			Scopes:      oauthScopes,
			RedirectURL: ext.RedirectURI,
		},
	}, nil
}

func (t tiktokProvider) AuthCodeURL(state string, args ...oauth2.AuthCodeOption) string {
	opts := make([]oauth2.AuthCodeOption, 0, len(args)+2)
	opts = append(opts, oauth2.SetAuthURLParam("client_key", t.Config.ClientID))
	opts = append(opts, oauth2.SetAuthURLParam("scope", strings.Join(t.Config.Scopes, ",")))
	opts = append(opts, args...)

	authURL := t.Config.AuthCodeURL(state, opts...)
	if authURL != "" {
		if u, err := url.Parse(authURL); err != nil {
			u.RawQuery = strings.ReplaceAll(u.RawQuery, "+", ",")
			authURL = u.String()
		}
	}
	return authURL
}

func (t tiktokProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	opts := make([]oauth2.AuthCodeOption, 0, 1)
	opts = append(opts, oauth2.SetAuthURLParam("client_key", t.Config.ClientID))
	return t.Exchange(context.Background(), code, opts...)
}

func (t tiktokProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	var u tiktokUserResponse

	fields := []string{
		"open_id",
		"union_id",
		"display_name",
		"avatar_url",
		"avatar_large_url",
	}
	if slices.Contains(t.Scopes, "user.info.profile") {
		fields = append(fields, []string{
			"bio_description",
			"profile_deep_link",
			"username",
			"is_verified",
		}...)
	}
	if slices.Contains(t.Scopes, "user.info.stats") {
		fields = append(fields, []string{
			"follower_count",
			"following_count",
			"likes_count",
			"video_count",
		}...)
	}
	params := url.Values{}
	params.Add("fields", strings.Join(fields, ","))

	req, err := http.NewRequest("GET", "https://open.tiktokapis.com/v2/user/info/?"+params.Encode(), nil)
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

	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return nil, err
	}
	if u.Error.Code != "ok" {
		return nil, errors.New(u.Error.Message)
	}

	return &UserProvidedData{
		Emails: []Email{
			{
				Email:    "",
				Verified: false,
				Primary:  false,
			},
		},
		Metadata: &Claims{
			Issuer:            defaultTikTokIssuerURL,
			Subject:           u.Data.User.ID,
			Name:              u.Data.User.DisplayName,
			Picture:           u.Data.User.AvatarUrl,
			PreferredUsername: u.Data.User.Username,
			UserNameKey:       u.Data.User.Username,
			Profile:           u.Data.User.ProfileDeepLink,
			CustomClaims: map[string]interface{}{
				"access_token":    tok,
				"scopes":          strings.Join(t.Scopes, ","),
				"is_verified":     u.Data.User.IsVerified,
				"union_id":        u.Data.User.UnionID,
				"follower_count":  u.Data.User.FollowerCount,
				"following_count": u.Data.User.FollowingCount,
				"likes_count":     u.Data.User.LikesCount,
				"video_count":     u.Data.User.VideoCount,
			},

			// To be deprecated
			AvatarURL:  u.Data.User.AvatarUrl,
			FullName:   u.Data.User.DisplayName,
			ProviderId: u.Data.User.ID,
		},
	}, nil
}
