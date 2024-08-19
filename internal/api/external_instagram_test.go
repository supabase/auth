package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"

	jwt "github.com/golang-jwt/jwt/v5"
)

const (
	instagramUser        string = `{"id":"instagramTestId","username":"instagram_test"}`
	instagramUserWrongID string = `{"id":"wrongTestId","username":"instagram_test"}`
)

func (ts *ExternalTestSuite) TestSignupExternalInstagram() {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/authorize?provider=instagram", nil)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)
	u, err := url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")
	q := u.Query()
	ts.Equal(ts.Config.External.Instagram.RedirectURI, q.Get("redirect_uri"))
	ts.Equal(ts.Config.External.Instagram.ClientID, []string{q.Get("client_id")})
	ts.Equal("code", q.Get("response_type"))
	ts.Equal("user_profile", q.Get("scope"))

	claims := ExternalProviderClaims{}
	p := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}))
	_, err = p.ParseWithClaims(q.Get("state"), &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(ts.Config.JWT.Secret), nil
	})
	ts.Require().NoError(err)

	ts.Equal("instagram", claims.Provider)
	ts.Equal(ts.Config.SiteURL, claims.SiteURL)
}

func InstagramTestSignupSetup(ts *ExternalTestSuite, tokenCount *int, userCount *int, code string, user string) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/access_token":
			*tokenCount++
			ts.Equal(code, r.FormValue("code"))
			ts.Equal("authorization_code", r.FormValue("grant_type"))
			ts.Equal(ts.Config.External.Instagram.RedirectURI, r.FormValue("redirect_uri"))

			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"instagram_token","user_id":"instagramTestId"}`)
		case "/me":
			*userCount++
			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, user)
		default:
			w.WriteHeader(500)
			ts.Fail("unknown instagram oauth call %s", r.URL.Path)
		}
	}))

	ts.Config.External.Instagram.URL = server.URL

	return server
}

func (ts *ExternalTestSuite) TestSignupExternalInstagram_AuthorizationCode() {
	ts.Config.DisableSignup = false
	tokenCount, userCount := 0, 0
	code := "authcode"
	server := InstagramTestSignupSetup(ts, &tokenCount, &userCount, code, instagramUser)
	defer server.Close()

	u := performAuthorization(ts, "instagram", code, "")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "", "instagram_test", "instagramTestId", "")
}

func (ts *ExternalTestSuite) TestSignupExternalInstagramDisableSignupErrorWhenNoUser() {
	ts.Config.DisableSignup = true

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := InstagramTestSignupSetup(ts, &tokenCount, &userCount, code, instagramUser)
	defer server.Close()

	u := performAuthorization(ts, "instagram", code, "")

	assertAuthorizationFailure(ts, u, "Signups not allowed for this instance", "access_denied", "")
}

func (ts *ExternalTestSuite) TestSignupExternalInstagramDisableSignupSuccessWithExistingUser() {
	ts.Config.DisableSignup = true

	ts.createUser("instagramTestId", "", "instagram_test", "", "")

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := InstagramTestSignupSetup(ts, &tokenCount, &userCount, code, instagramUser)
	defer server.Close()

	u := performAuthorization(ts, "instagram", code, "")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "", "instagram_test", "instagramTestId", "")
}

func (ts *ExternalTestSuite) TestInviteTokenExternalInstagramSuccessWhenMatchingToken() {
	ts.createUser("instagramTestId", "", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := InstagramTestSignupSetup(ts, &tokenCount, &userCount, code, instagramUser)
	defer server.Close()

	u := performAuthorization(ts, "instagram", code, "invite_token")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "", "instagram_test", "instagramTestId", "")
}

func (ts *ExternalTestSuite) TestInviteTokenExternalInstagramErrorWhenNoMatchingToken() {
	tokenCount, userCount := 0, 0
	code := "authcode"
	server := InstagramTestSignupSetup(ts, &tokenCount, &userCount, code, instagramUser)
	defer server.Close()

	w := performAuthorizationRequest(ts, "instagram", "invite_token")
	ts.Require().Equal(http.StatusNotFound, w.Code)
}

func (ts *ExternalTestSuite) TestInviteTokenExternalInstagramErrorWhenWrongToken() {
	ts.createUser("instagramTestId", "", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := InstagramTestSignupSetup(ts, &tokenCount, &userCount, code, instagramUser)
	defer server.Close()

	w := performAuthorizationRequest(ts, "instagram", "wrong_token")
	ts.Require().Equal(http.StatusNotFound, w.Code)
}

func (ts *ExternalTestSuite) TestInviteTokenExternalInstagramErrorWhenIDDoesntMatch() {
	ts.createUser("instagramTestId", "", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := InstagramTestSignupSetup(ts, &tokenCount, &userCount, code, instagramUserWrongID)
	defer server.Close()

	u := performAuthorization(ts, "instagram", code, "invite_token")

	assertAuthorizationFailure(ts, u, "User ID from external provider doesn't match invited user", "invalid_request", "")
}
