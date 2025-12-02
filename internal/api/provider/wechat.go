package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/supabase/auth/internal/conf"
	"golang.org/x/oauth2"
)

const (
	defaultWechatAuthBase = "open.weixin.qq.com"
	defaultWechatAPIBase  = "api.weixin.qq.com"
)

type wechatProvider struct {
	*oauth2.Config
	APIHost string
}

type wechatUser struct {
	OpenID     string   `json:"openid"`
	Nickname   string   `json:"nickname"`
	Sex        int      `json:"sex"`
	Province   string   `json:"province"`
	City       string   `json:"city"`
	Country    string   `json:"country"`
	HeadImgURL string   `json:"headimgurl"`
	Privilege  []string `json:"privilege"`
	UnionID    string   `json:"unionid"`
}

type wechatTokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	OpenID       string `json:"openid"`
	Scope        string `json:"scope"`
	UnionID      string `json:"unionid"`

	// Error fields
	ErrCode int    `json:"errcode"`
	ErrMsg  string `json:"errmsg"`
}

// NewWechatProvider creates a WeChat account provider.
func NewWechatProvider(ext conf.OAuthProviderConfiguration) (OAuthProvider, error) {
	if err := ext.ValidateOAuth(); err != nil {
		return nil, err
	}

	authHost := chooseHost(ext.URL, defaultWechatAuthBase)
	apiHost := chooseHost(ext.URL, defaultWechatAPIBase)

	return &wechatProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID[0],
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  fmt.Sprintf("%s/connect/qrconnect", authHost),
				TokenURL: fmt.Sprintf("%s/sns/oauth2/access_token", apiHost),
			},
			RedirectURL: ext.RedirectURI,
			Scopes:      []string{"snsapi_login"},
		},
		APIHost: apiHost,
	}, nil
}

func (w wechatProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	// WeChat uses a custom token exchange that doesn't follow standard OAuth2
	// We need to make a direct HTTP request instead of using oauth2.Exchange

	// Construct the token URL, handling the case where APIHost might already include protocol
	var tokenURL = fmt.Sprintf("%s/sns/oauth2/access_token?appid=%s&secret=%s&code=%s&grant_type=authorization_code",
		w.APIHost, w.ClientID, w.ClientSecret, code)

	resp, err := http.Get(tokenURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get access token: %w", err)
	}
	defer resp.Body.Close()

	var tokenResp wechatTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	if tokenResp.ErrCode != 0 {
		return nil, fmt.Errorf("wechat api error: %d - %s", tokenResp.ErrCode, tokenResp.ErrMsg)
	}

	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("empty access token received")
	}

	// Convert to standard oauth2.Token
	token := &oauth2.Token{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		TokenType:    "Bearer",
	}

	// Store additional WeChat-specific information in token extras
	extras := make(map[string]interface{})
	extras["openid"] = tokenResp.OpenID
	extras["scope"] = tokenResp.Scope
	if tokenResp.UnionID != "" {
		extras["unionid"] = tokenResp.UnionID
	}
	token = token.WithExtra(extras)

	return token, nil
}

func (w wechatProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	// Extract openid from token extras
	openid, ok := tok.Extra("openid").(string)
	if !ok || openid == "" {
		return nil, fmt.Errorf("openid not found in token")
	}

	// Build user info URL
	var userURL = fmt.Sprintf("%s/sns/userinfo?access_token=%s&openid=%s&lang=zh_CN",
		w.APIHost, url.QueryEscape(tok.AccessToken), url.QueryEscape(openid))
	req, err := http.NewRequestWithContext(ctx, "GET", userURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	var user wechatUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("failed to decode user response: %w", err)
	}

	if user.OpenID == "" {
		return nil, fmt.Errorf("invalid user data received")
	}

	// Build user data
	data := &UserProvidedData{
		Metadata: &Claims{
			Issuer:  fmt.Sprintf("https://%s", w.APIHost),
			Subject: user.OpenID,
			Name:    user.Nickname,
			Picture: user.HeadImgURL,
			Locale:  "zh_CN",

			// Custom claims for WeChat-specific data
			CustomClaims: map[string]interface{}{
				"openid":    user.OpenID,
				"unionid":   user.UnionID,
				"sex":       user.Sex,
				"province":  user.Province,
				"city":      user.City,
				"country":   user.Country,
				"privilege": user.Privilege,
			},

			// Deprecated fields for backward compatibility
			AvatarURL:   user.HeadImgURL,
			FullName:    user.Nickname,
			ProviderId:  user.OpenID,
			UserNameKey: user.Nickname,
		},
	}

	// WeChat doesn't provide email, so we create a synthetic email using openid
	// This ensures the user can be uniquely identified in the system
	syntheticEmail := user.OpenID + "@wechat.local"
	data.Emails = []Email{
		{
			Email:    syntheticEmail,
			Verified: true, // We consider the WeChat account as verified
			Primary:  true,
		},
	}

	return data, nil
}

// AuthCodeURL generates the URL for WeChat OAuth authorization
func (w wechatProvider) AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string {
	// WeChat uses different parameter names and structure than standard OAuth2
	// We need to construct the URL manually since WeChat doesn't follow OAuth2 standards exactly
	params := url.Values{
		"appid":         {w.ClientID},
		"redirect_uri":  {w.RedirectURL},
		"response_type": {"code"},
		"scope":         {"snsapi_login"},
	}

	if state != "" {
		params.Set("state", state)
	}

	authURL := fmt.Sprintf("https://%s/connect/qrconnect?%s#wechat_redirect",
		defaultWechatAuthBase, params.Encode())

	return authURL
}
