package provider

import (
	"context"
	"github.com/supabase/gotrue/internal/conf"
	"golang.org/x/oauth2"
	"net/http"
	"sync"
)

var (
	WechatCacheMap map[string]WechatCacheMapValue
	Lock           sync.RWMutex
)

type WechatCacheMapValue struct {
	IsScanned     bool
	WechatUnionId string
}

type weChatProvider struct {
	Client *http.Client
	Config *oauth2.Config
}

type WechatUser struct {
	Openid     string   `json:"openid"`   // The ID of an ordinary user, which is unique to the current developer account
	Nickname   string   `json:"nickname"` // Ordinary user nickname
	Sex        int      `json:"sex"`      // Ordinary user gender, 1 is male, 2 is female
	Language   string   `json:"language"`
	City       string   `json:"city"`       // City filled in by general user's personal data
	Province   string   `json:"province"`   // Province filled in by ordinary user's personal information
	Country    string   `json:"country"`    // Country, such as China is CN
	Headimgurl string   `json:"headimgurl"` // User avatar, the last value represents the size of the square avatar (there are optional values of 0, 46, 64, 96, 132, 0 represents a 640*640 square avatar), this item is empty when the user does not have an avatar
	Privilege  []string `json:"privilege"`  // User Privilege information, json array, such as Wechat Woka user (chinaunicom)
	Unionid    string   `json:"unionid"`    // Unified user identification. For an application under a WeChat open platform account, the unionid of the same user is unique.
}

func NewWeChatIdProvider(clientId string, clientSecret string, redirectUrl string, ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	//idp := &WeChatIdProvider{}
	//
	//config := idp.getConfig(clientId, clientSecret, redirectUrl)
	//idp.Config = config
	//if scopes == "" {
	//	scopes = "logs"
	//}
	//
	//return &weChatProvider{
	//	Config: &oauth2.Config{
	//		ClientID:     ext.ClientID[0],
	//		ClientSecret: ext.Secret,
	//		Endpoint: oauth2.Endpoint{
	//			AuthURL:  authHost + "/login/oauth/authorize",
	//			TokenURL: authHost + "/login/oauth/access_token",
	//		},
	//		RedirectURL: ext.RedirectURI,
	//		Scopes:      oauthScopes,
	//	},
	//	APIHost: apiHost,
	//}, nil
	return nil, nil
}

func (p weChatProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return nil, nil
}

func (p weChatProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	return nil, nil
}
