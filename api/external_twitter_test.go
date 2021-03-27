package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"

	jwt "github.com/dgrijalva/jwt-go"
)

func (ts *ExternalTestSuite) TestSignupExternalTwitter() {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/authorize?provider=twitter", nil)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)
	u, err := url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")
	q := u.Query()
	ts.Equal(ts.Config.External.Twitter.RedirectURI, q.Get("redirect_uri"))
	ts.Equal(ts.Config.External.Twitter.ClientID, q.Get("client_id"))
	ts.Equal("code", q.Get("response_type"))
	ts.Equal("email", q.Get("scope"))

	claims := ExternalProviderClaims{}
	p := jwt.Parser{ValidMethods: []string{jwt.SigningMethodHS256.Name}}
	_, err = p.ParseWithClaims(q.Get("state"), &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(ts.API.config.OperatorToken), nil
	})
	ts.Require().NoError(err)

	ts.Equal("twitter", claims.Provider)
	ts.Equal(ts.Config.SiteURL, claims.SiteURL)
}

func TwitterTestSignupSetup(ts *ExternalTestSuite, tokenCount *int, userCount *int, code string, user string) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/access_token":
			*tokenCount++
			ts.Equal(code, r.FormValue("code"))
			ts.Equal("authorization_code", r.FormValue("grant_type"))
			ts.Equal(ts.Config.External.Twitter.RedirectURI, r.FormValue("redirect_uri"))

			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"twitter_token","expires_in":100000}`)
		case "/me":
			*userCount++
			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, user)
		default:
			w.WriteHeader(500)
			ts.Fail("unknown twitter oauth call %s", r.URL.Path)
		}
	}))

	ts.Config.External.Twitter.URL = server.URL

	return server
}

func (ts *ExternalTestSuite) TestSignupExternalTwitter_AuthorizationCode() {
	ts.Config.DisableSignup = false
	tokenCount, userCount := 0, 0
	code := "authcode"
	twitterUser := `{"name":"Twitter Test","first_name":"Twitter","last_name":"Test","email":"twitter@example.com","picture":{"data":{"url":"http://example.com/avatar"}}}}`
	server := TwitterTestSignupSetup(ts, &tokenCount, &userCount, code, twitterUser)
	defer server.Close()

	u := performAuthorization(ts, "twitter", code, "")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "twitter@example.com", "Twitter Test", "http://example.com/avatar")
}

func (ts *ExternalTestSuite) TestSignupExternalTwitterDisableSignupErrorWhenNoUser() {
	ts.Config.DisableSignup = true

	tokenCount, userCount := 0, 0
	code := "authcode"
	twitterUser := `{"name":"Twitter Test","first_name":"Twitter","last_name":"Test","email":"twitter@example.com","picture":{"data":{"url":"http://example.com/avatar"}}}}`
	server := TwitterTestSignupSetup(ts, &tokenCount, &userCount, code, twitterUser)
	defer server.Close()

	u := performAuthorization(ts, "twitter", code, "")

	assertAuthorizationFailure(ts, u, "Signups not allowed for this instance", "access_denied", "twitter@example.com")
}
func (ts *ExternalTestSuite) TestSignupExternalTwitterDisableSignupErrorWhenEmptyEmail() {
	ts.Config.DisableSignup = true

	tokenCount, userCount := 0, 0
	code := "authcode"
	twitterUser := `{"name":"Twitter Test","first_name":"Twitter","last_name":"Test","picture":{"data":{"url":"http://example.com/avatar"}}}}`
	server := TwitterTestSignupSetup(ts, &tokenCount, &userCount, code, twitterUser)
	defer server.Close()

	u := performAuthorization(ts, "twitter", code, "")

	assertAuthorizationFailure(ts, u, "Error getting user email from external provider", "server_error", "twitter@example.com")
}

func (ts *ExternalTestSuite) TestSignupExternalTwitterDisableSignupSuccessWithPrimaryEmail() {
	ts.Config.DisableSignup = true

	ts.createUser("twitter@example.com", "Twitter Test", "http://example.com/avatar", "")

	tokenCount, userCount := 0, 0
	code := "authcode"
	twitterUser := `{"name":"Twitter Test","first_name":"Twitter","last_name":"Test","email":"twitter@example.com","picture":{"data":{"url":"http://example.com/avatar"}}}}`
	server := TwitterTestSignupSetup(ts, &tokenCount, &userCount, code, twitterUser)
	defer server.Close()

	u := performAuthorization(ts, "twitter", code, "")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "twitter@example.com", "Twitter Test", "http://example.com/avatar")
}

func (ts *ExternalTestSuite) TestInviteTokenExternalTwitterSuccessWhenMatchingToken() {
	// name and avatar should be populated from Twitter API
	ts.createUser("twitter@example.com", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	twitterUser := `{"name":"Twitter Test","first_name":"Twitter","last_name":"Test","email":"twitter@example.com","picture":{"data":{"url":"http://example.com/avatar"}}}}`
	server := TwitterTestSignupSetup(ts, &tokenCount, &userCount, code, twitterUser)
	defer server.Close()

	u := performAuthorization(ts, "twitter", code, "invite_token")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "twitter@example.com", "Twitter Test", "http://example.com/avatar")
}

func (ts *ExternalTestSuite) TestInviteTokenExternalTwitterErrorWhenNoMatchingToken() {
	tokenCount, userCount := 0, 0
	code := "authcode"
	twitterUser := `{"name":"Twitter Test","first_name":"Twitter","last_name":"Test","email":"twitter@example.com","picture":{"data":{"url":"http://example.com/avatar"}}}}`
	server := TwitterTestSignupSetup(ts, &tokenCount, &userCount, code, twitterUser)
	defer server.Close()

	w := performAuthorizationRequest(ts, "twitter", "invite_token")
	ts.Require().Equal(http.StatusNotFound, w.Code)
}

func (ts *ExternalTestSuite) TestInviteTokenExternalTwitterErrorWhenWrongToken() {
	ts.createUser("twitter@example.com", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	twitterUser := `{"name":"Twitter Test","first_name":"Twitter","last_name":"Test","email":"twitter@example.com","picture":{"data":{"url":"http://example.com/avatar"}}}}`
	server := TwitterTestSignupSetup(ts, &tokenCount, &userCount, code, twitterUser)
	defer server.Close()

	w := performAuthorizationRequest(ts, "twitter", "wrong_token")
	ts.Require().Equal(http.StatusNotFound, w.Code)
}

func (ts *ExternalTestSuite) TestInviteTokenExternalTwitterErrorWhenEmailDoesntMatch() {
	ts.createUser("twitter@example.com", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	twitterUser := `{"name":"Twitter Test","first_name":"Twitter","last_name":"Test","email":"other@example.com","picture":{"data":{"url":"http://example.com/avatar"}}}}`
	server := TwitterTestSignupSetup(ts, &tokenCount, &userCount, code, twitterUser)
	defer server.Close()

	u := performAuthorization(ts, "twitter", code, "invite_token")

	assertAuthorizationFailure(ts, u, "Invited email does not match emails from external provider", "invalid_request", "")
}
