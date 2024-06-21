package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/supabase/gotrue/internal/conf"
	"golang.org/x/oauth2"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type WechatAccessToken struct {
	AccessToken  string `json:"access_token"`  // Interface call credentials
	ExpiresIn    int64  `json:"expires_in"`    // access_token interface call credential timeout time, unit (seconds)
	RefreshToken string `json:"refresh_token"` // User refresh access_token
	Openid       string `json:"openid"`        // Unique ID of authorized user
	Scope        string `json:"scope"`         // The scope of user authorization, separated by commas. (,)
	Unionid      string `json:"unionid"`       // This field will appear if and only if the website application has been authorized by the user's UserInfo.
}

var (
	WechatCacheMap map[string]WechatCacheMapValue
	Lock           sync.RWMutex
)

type WechatCacheMapValue struct {
	IsScanned     bool
	WechatUnionId string
}

type Config struct {
	AppID       string
	Secret      string
	Endpoint    oauth2.Endpoint
	RedirectURL string
	Scopes      []string
}

type weChatProvider struct {
	Client *http.Client
	*oauth2.Config
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

func NewWeChatProvider(ext conf.OAuthProviderConfiguration) (OAuthProvider, error) {

	return &weChatProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID[0],
			ClientSecret: ext.Secret,
			RedirectURL:  ext.RedirectURI,
		},
	}, nil
}

func (idp weChatProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	if strings.HasPrefix(code, "wechat_oa:") {
		token := oauth2.Token{
			AccessToken: code,
			TokenType:   "WeChatAccessToken",
			Expiry:      time.Time{},
		}
		return &token, nil
	}

	params := url.Values{}
	params.Add("grant_type", "authorization_code")
	params.Add("appid", idp.Config.ClientID)
	params.Add("secret", idp.Config.ClientSecret)
	params.Add("code", code)

	accessTokenUrl := fmt.Sprintf("https://api.weixin.qq.com/sns/oauth2/access_token?%s", params.Encode())
	tokenResponse, err := idp.Client.Get(accessTokenUrl)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			return
		}
	}(tokenResponse.Body)
	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(tokenResponse.Body)
	if err != nil {
		return nil, err
	}

	if strings.Contains(buf.String(), "errcode") {
		return nil, fmt.Errorf(buf.String())
	}

	var wechatAccessToken WechatAccessToken
	if err = json.Unmarshal(buf.Bytes(), &wechatAccessToken); err != nil {
		return nil, err
	}

	token := oauth2.Token{
		AccessToken:  wechatAccessToken.AccessToken,
		TokenType:    "WeChatAccessToken",
		RefreshToken: wechatAccessToken.RefreshToken,
		Expiry:       time.Time{},
	}

	raw := make(map[string]string)
	raw["Openid"] = wechatAccessToken.Openid
	token.WithExtra(raw)

	return &token, nil
}

func (idp weChatProvider) GetUserData(ctx context.Context, token *oauth2.Token) (*UserProvidedData, error) {
	var wechatUser WechatUser
	if strings.HasPrefix(token.AccessToken, "wechat_oa:") {
		Lock.RLock()
		mapValue, ok := WechatCacheMap[token.AccessToken[10:]]
		Lock.RUnlock()

		if !ok || mapValue.WechatUnionId == "" {
			return nil, fmt.Errorf("error ticket")
		}

		Lock.Lock()
		delete(WechatCacheMap, token.AccessToken[10:])
		Lock.Unlock()

		userInfo := UserProvidedData{
			Metadata: &Claims{
				Id: mapValue.WechatUnionId,
			},
		}
		return &userInfo, nil
	}
	openid := token.Extra("Openid")

	userInfoUrl := fmt.Sprintf("https://api.weixin.qq.com/sns/userinfo?access_token=%s&openid=%s", token.AccessToken, openid)
	resp, err := idp.Client.Get(userInfoUrl)
	if err != nil {
		return nil, fmt.Errorf("get user info error: %v", err)

	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			return
		}
	}(resp.Body)
	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(resp.Body)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(buf.Bytes(), &wechatUser); err != nil {
		return nil, err
	}

	id := wechatUser.Unionid
	if id == "" {
		id = wechatUser.Openid
	}
	email := make([]Email, 0)
	email = append(email, Email{Email: wechatUser.Openid, Verified: true, Primary: true})
	userData := UserProvidedData{
		Emails: email,
		Metadata: &Claims{
			Id:       id,
			NickName: wechatUser.Nickname,
			Name:     wechatUser.Nickname,
			Picture:  wechatUser.Headimgurl,
			Gender:   mapGender(wechatUser.Sex),
			Email:    wechatUser.Openid,
		},
	}
	return &userData, nil
}

func mapGender(sex int) string {
	switch sex {
	case 1:
		return "male"
	case 2:
		return "female"
	default:
		return "unknown"
	}
}
