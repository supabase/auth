package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"

	jwt "github.com/golang-jwt/jwt/v5"
)

const (
	snapchatUser = `{"data":{"me":{"externalId":"snapchatTestId","displayName":"Snapchat Test","bitmoji":{"avatar":"http://example.com/bitmoji"}}}}`
)

func (ts *ExternalTestSuite) TestSignupExternalSnapchat() {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/authorize?provider=snapchat", nil)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)
	u, err := url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")
	q := u.Query()
	ts.Equal(ts.Config.External.Snapchat.RedirectURI, q.Get("redirect_uri"))
	ts.Equal(ts.Config.External.Snapchat.ClientID, []string{q.Get("client_id")})
	ts.Equal("code", q.Get("response_type"))
	ts.Equal("https://auth.snapchat.com/oauth2/api/user.external_id https://auth.snapchat.com/oauth2/api/user.display_name https://auth.snapchat.com/oauth2/api/user.bitmoji.avatar", q.Get("scope"))

	claims := ExternalProviderClaims{}
	p := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}))
	_, err = p.ParseWithClaims(q.Get("state"), &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(ts.Config.JWT.Secret), nil
	})
	ts.Require().NoError(err)

	ts.Equal("snapchat", claims.Provider)
	ts.Equal(ts.Config.SiteURL, claims.SiteURL)
}

func SnapchatTestSignupSetup(ts *ExternalTestSuite, tokenCount *int, userCount *int, code string, user string) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/accounts/oauth2/token":
			*tokenCount++
			ts.Equal(code, r.FormValue("code"))
			ts.Equal("authorization_code", r.FormValue("grant_type"))
			ts.Equal(ts.Config.External.Snapchat.RedirectURI, r.FormValue("redirect_uri"))

			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"snapchat_token","expires_in":3600}`)
		case "/v1/me":
			*userCount++
			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, user)
		default:
			w.WriteHeader(500)
			ts.Fail("unknown snapchat oauth call %s", r.URL.Path)
		}
	}))

	ts.Config.External.Snapchat.URL = server.URL

	return server
}

func (ts *ExternalTestSuite) TestSignupExternalSnapchat_AuthorizationCode() {
	ts.Config.DisableSignup = false
	tokenCount, userCount := 0, 0
	code := "authcode"
	server := SnapchatTestSignupSetup(ts, &tokenCount, &userCount, code, snapchatUser)
	defer server.Close()

	u := performAuthorization(ts, "snapchat", code, "")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "snapchattestid@snapchat.id", "Snapchat Test", "snapchatTestId", "http://example.com/bitmoji")
}

func (ts *ExternalTestSuite) TestSignupExternalSnapchatDisableSignupErrorWhenNoUser() {
	ts.Config.DisableSignup = true

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := SnapchatTestSignupSetup(ts, &tokenCount, &userCount, code, snapchatUser)
	defer server.Close()

	u := performAuthorization(ts, "snapchat", code, "")

	assertAuthorizationFailure(ts, u, "Signups not allowed for this instance", "access_denied", "")
}

func (ts *ExternalTestSuite) TestSignupExternalSnapchatDisableSignupSuccessWithExistingUser() {
	ts.Config.DisableSignup = true

	ts.createUser("snapchatTestId", "snapchattestid@snapchat.id", "Snapchat Test", "http://example.com/bitmoji", "")

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := SnapchatTestSignupSetup(ts, &tokenCount, &userCount, code, snapchatUser)
	defer server.Close()

	u := performAuthorization(ts, "snapchat", code, "")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "snapchattestid@snapchat.id", "Snapchat Test", "snapchatTestId", "http://example.com/bitmoji")
}

func (ts *ExternalTestSuite) TestInviteTokenExternalSnapchatSuccessWhenMatchingToken() {
	// name and avatar should be populated from Snapchat API
	// Use the same email that the provider will generate - converted to lowercase
	ts.createUser("snapchatTestId", "snapchattestid@snapchat.id", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := SnapchatTestSignupSetup(ts, &tokenCount, &userCount, code, snapchatUser)
	defer server.Close()

	u := performAuthorization(ts, "snapchat", code, "invite_token")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "snapchattestid@snapchat.id", "Snapchat Test", "snapchatTestId", "http://example.com/bitmoji")
}

func (ts *ExternalTestSuite) TestInviteTokenExternalSnapchatErrorWhenNoMatchingToken() {
	tokenCount, userCount := 0, 0
	code := "authcode"
	server := SnapchatTestSignupSetup(ts, &tokenCount, &userCount, code, snapchatUser)
	defer server.Close()

	w := performAuthorizationRequest(ts, "snapchat", "invite_token")
	ts.Require().Equal(http.StatusNotFound, w.Code)
}

func (ts *ExternalTestSuite) TestInviteTokenExternalSnapchatErrorWhenWrongToken() {
	ts.createUser("snapchatTestId", "", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := SnapchatTestSignupSetup(ts, &tokenCount, &userCount, code, snapchatUser)
	defer server.Close()

	w := performAuthorizationRequest(ts, "snapchat", "wrong_token")
	ts.Require().Equal(http.StatusNotFound, w.Code)
}
