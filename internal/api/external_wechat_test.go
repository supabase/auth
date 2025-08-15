package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/models"
)

func (ts *ExternalTestSuite) TestSignupExternalWechat() {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/authorize?provider=wechat", nil)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)
	u, err := url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")
	q := u.Query()
	ts.Equal(ts.Config.External.Wechat.RedirectURI, q.Get("redirect_uri"))
	ts.Equal(ts.Config.External.Wechat.ClientID, []string{q.Get("appid")})
	ts.Equal("code", q.Get("response_type"))
	ts.Equal("snsapi_login", q.Get("scope"))

	claims := ExternalProviderClaims{}
	p := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}))
	_, err = p.ParseWithClaims(q.Get("state"), &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(ts.Config.JWT.Secret), nil
	})
	ts.Require().NoError(err)

	ts.Equal("wechat", claims.Provider)
	ts.Equal(ts.Config.SiteURL, claims.SiteURL)
}

func WechatTestSignupSetup(ts *ExternalTestSuite, tokenCount *int, userCount *int, code string, openid string, nickname string, unionid string) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sns/oauth2/access_token":
			*tokenCount++
			ts.Equal(code, r.URL.Query().Get("code"))
			ts.Equal("authorization_code", r.URL.Query().Get("grant_type"))
			ts.Equal(ts.Config.External.Wechat.ClientID[0], r.URL.Query().Get("appid"))
			ts.Equal(ts.Config.External.Wechat.Secret, r.URL.Query().Get("secret"))

			w.Header().Add("Content-Type", "application/json")
			tokenResp := map[string]interface{}{
				"access_token":  "wechat_token",
				"expires_in":    7200,
				"refresh_token": "wechat_refresh_token",
				"openid":        openid,
				"scope":         "snsapi_login",
			}
			if unionid != "" {
				tokenResp["unionid"] = unionid
			}
			json.NewEncoder(w).Encode(tokenResp)

		case "/sns/userinfo":
			*userCount++
			ts.Equal("wechat_token", r.URL.Query().Get("access_token"))
			ts.Equal(openid, r.URL.Query().Get("openid"))

			w.Header().Add("Content-Type", "application/json")
			userResp := map[string]interface{}{
				"openid":     openid,
				"nickname":   nickname,
				"sex":        1,
				"province":   "guangdong",
				"city":       "shenzhen",
				"country":    "cn",
				"headimgurl": "http://thirdwx.qlogo.cn/mmopen/test.jpg",
				"privilege":  []string{"chinaunicom"},
			}
			if unionid != "" {
				userResp["unionid"] = unionid
			}
			json.NewEncoder(w).Encode(userResp)

		default:
			w.WriteHeader(500)
			ts.Fail("unknown wechat oauth call %s", r.URL.Path)
		}
	}))

	ts.Config.External.Wechat.URL = server.URL

	return server
}

func (ts *ExternalTestSuite) TestSignupExternalWechat_AuthorizationCode() {
	tokenCount, userCount := 0, 0
	code := "authcode"
	openid := "wechat_openid_123"
	nickname := "wechat_test"
	unionid := "wechat_unionid_456"
	server := WechatTestSignupSetup(ts, &tokenCount, &userCount, code, openid, nickname, unionid)
	defer server.Close()

	u := performAuthorization(ts, "wechat", code, "")

	// WeChat doesn't provide email, so we use openid as the identifier
	// The user should be created with openid as the primary identifier
	assertWechatAuthorizationSuccess(ts, u, tokenCount, userCount, openid, nickname, "http://thirdwx.qlogo.cn/mmopen/test.jpg", unionid)
}

func (ts *ExternalTestSuite) TestSignupExternalWechatDisableSignupErrorWhenNoUser() {
	ts.Config.DisableSignup = true
	tokenCount, userCount := 0, 0
	code := "authcode"
	openid := "wechat_openid_123"
	nickname := "wechat_test"
	unionid := "wechat_unionid_456"
	server := WechatTestSignupSetup(ts, &tokenCount, &userCount, code, openid, nickname, unionid)
	defer server.Close()

	u := performAuthorization(ts, "wechat", code, "")

	assertAuthorizationFailure(ts, u, "Signups not allowed for this instance", "access_denied", "")
}

func (ts *ExternalTestSuite) TestSignupExternalWechatDisableSignupSuccessWithExistingUser() {
	ts.Config.DisableSignup = true

	// Create user with WeChat openid as the email field (since WeChat doesn't provide email)
	openid := "wechat_openid_123"
	ts.createUser(openid, openid+"@wechat.local", "wechat_test", "http://thirdwx.qlogo.cn/mmopen/test.jpg", "")

	tokenCount, userCount := 0, 0
	code := "authcode"
	nickname := "wechat_test"
	unionid := "wechat_unionid_456"
	server := WechatTestSignupSetup(ts, &tokenCount, &userCount, code, openid, nickname, unionid)
	defer server.Close()

	u := performAuthorization(ts, "wechat", code, "")

	assertWechatAuthorizationSuccess(ts, u, tokenCount, userCount, openid, nickname, "http://thirdwx.qlogo.cn/mmopen/test.jpg", unionid)
}

func (ts *ExternalTestSuite) TestInviteTokenExternalWechatSuccessWhenMatchingToken() {
	// name and avatar should be populated from WeChat API
	openid := "wechat_openid_123"
	ts.createUser(openid, openid+"@wechat.local", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	nickname := "wechat_test"
	unionid := "wechat_unionid_456"
	server := WechatTestSignupSetup(ts, &tokenCount, &userCount, code, openid, nickname, unionid)
	defer server.Close()

	u := performAuthorization(ts, "wechat", code, "invite_token")

	assertWechatAuthorizationSuccess(ts, u, tokenCount, userCount, openid, nickname, "http://thirdwx.qlogo.cn/mmopen/test.jpg", unionid)
}

func (ts *ExternalTestSuite) TestInviteTokenExternalWechatErrorWhenNoMatchingToken() {
	tokenCount, userCount := 0, 0
	code := "authcode"
	openid := "wechat_openid_123"
	nickname := "wechat_test"
	unionid := "wechat_unionid_456"
	server := WechatTestSignupSetup(ts, &tokenCount, &userCount, code, openid, nickname, unionid)
	defer server.Close()

	w := performAuthorizationRequest(ts, "wechat", "invite_token")
	ts.Require().Equal(http.StatusNotFound, w.Code)
}

func (ts *ExternalTestSuite) TestInviteTokenExternalWechatErrorWhenWrongToken() {
	openid := "wechat_openid_123"
	ts.createUser(openid, openid+"@wechat.local", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	nickname := "wechat_test"
	unionid := "wechat_unionid_456"
	server := WechatTestSignupSetup(ts, &tokenCount, &userCount, code, openid, nickname, unionid)
	defer server.Close()

	w := performAuthorizationRequest(ts, "wechat", "wrong_token")
	ts.Require().Equal(http.StatusNotFound, w.Code)
}

func (ts *ExternalTestSuite) TestSignupExternalWechatErrorWhenUserBanned() {
	tokenCount, userCount := 0, 0
	code := "authcode"
	openid := "wechat_openid_123"
	nickname := "wechat_test"
	unionid := "wechat_unionid_456"
	server := WechatTestSignupSetup(ts, &tokenCount, &userCount, code, openid, nickname, unionid)
	defer server.Close()

	u := performAuthorization(ts, "wechat", code, "")
	assertWechatAuthorizationSuccess(ts, u, tokenCount, userCount, openid, nickname, "http://thirdwx.qlogo.cn/mmopen/test.jpg", unionid)

	// Find user by the generated email (openid@wechat.local)
	user, err := models.FindUserByEmailAndAudience(ts.API.db, openid+"@wechat.local", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	t := time.Now().Add(24 * time.Hour)
	user.BannedUntil = &t
	require.NoError(ts.T(), ts.API.db.UpdateOnly(user, "banned_until"))

	u = performAuthorization(ts, "wechat", code, "")
	assertAuthorizationFailure(ts, u, "User is banned", "access_denied", "")
}

func (ts *ExternalTestSuite) TestSignupExternalWechatTokenError() {
	tokenCount := 0
	code := "authcode"

	// Mock server that returns an error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sns/oauth2/access_token":
			tokenCount++
			w.Header().Add("Content-Type", "application/json")
			errorResp := map[string]interface{}{
				"errcode": 40029,
				"errmsg":  "invalid code",
			}
			json.NewEncoder(w).Encode(errorResp)
		default:
			w.WriteHeader(500)
			ts.Fail("unknown wechat oauth call %s", r.URL.Path)
		}
	}))
	defer server.Close()

	ts.Config.External.Wechat.URL = server.URL

	u := performAuthorization(ts, "wechat", code, "")

	// Should get an error
	v, err := url.ParseQuery(u.RawQuery)
	ts.Require().NoError(err)
	ts.Require().NotEmpty(v.Get("error_description"))
	ts.Require().Equal("server_error", v.Get("error"))
}

// Helper function specific to WeChat since it doesn't provide email
func assertWechatAuthorizationSuccess(ts *ExternalTestSuite, u *url.URL, tokenCount int, userCount int, openid string, name string, avatar string, unionid string) {
	// ensure redirect has #access_token=...
	v, err := url.ParseQuery(u.RawQuery)
	ts.Require().NoError(err)
	ts.Require().Empty(v.Get("error_description"))
	ts.Require().Empty(v.Get("error"))

	v, err = url.ParseQuery(u.Fragment)
	ts.Require().NoError(err)
	ts.NotEmpty(v.Get("access_token"))
	ts.NotEmpty(v.Get("refresh_token"))
	ts.NotEmpty(v.Get("expires_in"))
	ts.Equal("bearer", v.Get("token_type"))

	ts.Equal(1, tokenCount)
	if userCount > -1 {
		ts.Equal(1, userCount)
	}

	// For WeChat, we need to find user by the generated email (openid@wechat.local)
	// since WeChat doesn't provide email addresses
	email := openid + "@wechat.local"
	user, err := models.FindUserByEmailAndAudience(ts.API.db, email, ts.Config.JWT.Aud)
	ts.Require().NoError(err)
	ts.Equal(openid, user.UserMetaData["provider_id"])
	ts.Equal(name, user.UserMetaData["full_name"])
	if avatar == "" {
		ts.Equal(nil, user.UserMetaData["avatar_url"])
	} else {
		ts.Equal(avatar, user.UserMetaData["avatar_url"])
	}

	// Check WeChat-specific metadata
	if unionid != "" {
		customClaims, ok := user.UserMetaData["custom_claims"]
		ts.Require().True(ok, "custom_claims should exist in user metadata")
		customClaimsMap, ok := customClaims.(map[string]interface{})
		ts.Require().True(ok, "custom_claims should be a map")
		ts.Equal(unionid, customClaimsMap["unionid"])
		ts.Equal(openid, customClaimsMap["openid"])
	}
}
