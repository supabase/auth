package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"

	jwt "github.com/golang-jwt/jwt"
)

const (
	yahooUser        string = `{"sub": "yahootestid", "name": "Yahoocloak Test", "email": "yahoo@example.com", "preferred_username": "yahoo", "email_verified": true}`
	yahooUserNoEmail string = `{"sub": "yahootestid", "name": "Yahoo Test", "preferred_username": "yahoo", "email_verified": false}`
)

func (ts *ExternalTestSuite) TestSignupExternalYahoo() {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/authorize?provider=yahoo", nil)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)
	u, err := url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")
	q := u.Query()
	ts.Equal(ts.Config.External.Yahoo.RedirectURI, q.Get("redirect_uri"))
	ts.Equal(ts.Config.External.Yahoo.ClientID, []string{q.Get("client_id")})
	ts.Equal("code", q.Get("response_type"))
	ts.Equal("profile email", q.Get("scope"))

	claims := ExternalProviderClaims{}
	p := jwt.Parser{ValidMethods: []string{jwt.SigningMethodHS256.Name}}
	_, err = p.ParseWithClaims(q.Get("state"), &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(ts.Config.JWT.Secret), nil
	})
	ts.Require().NoError(err)

	ts.Equal("yahoo", claims.Provider)
	ts.Equal(ts.Config.SiteURL, claims.SiteURL)
}

func YahooTestSignupSetup(ts *ExternalTestSuite, tokenCount *int, userCount *int, code string, user string) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/protocol/openid-connect/token":
			*tokenCount++
			ts.Equal(code, r.FormValue("code"))
			ts.Equal("authorization_code", r.FormValue("grant_type"))
			ts.Equal(ts.Config.External.Yahoo.RedirectURI, r.FormValue("redirect_uri"))

			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"yahoo_token","expires_in":100000}`)
		case "/protocol/openid-connect/userinfo":
			*userCount++
			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, user)
		default:
			w.WriteHeader(500)
			ts.Fail("unknown yahoo oauth call %s", r.URL.Path)
		}
	}))

	ts.Config.External.Yahoo.URL = server.URL

	return server
}

func (ts *ExternalTestSuite) TestSignupExternalYahooWithoutURLSetup() {
	ts.createUser("yahootestid", "yahoo@example.com", "Yahoo Test", "", "")
	tokenCount, userCount := 0, 0
	code := "authcode"
	server := YahooTestSignupSetup(ts, &tokenCount, &userCount, code, yahooUser)
	ts.Config.External.Yahoo.URL = ""
	defer server.Close()

	w := performAuthorizationRequest(ts, "yahoo", code)
	ts.Equal(w.Code, http.StatusBadRequest)
}

func (ts *ExternalTestSuite) TestSignupExternalYahoo_AuthorizationCode() {
	ts.Config.DisableSignup = false
	ts.createUser("yahootestid", "yahoo@example.com", "Yahoo Test", "http://example.com/avatar", "")
	tokenCount, userCount := 0, 0
	code := "authcode"
	server := YahooTestSignupSetup(ts, &tokenCount, &userCount, code, yahooUser)
	defer server.Close()

	u := performAuthorization(ts, "yahoo", code, "")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "yahoo@example.com", "Yahoo Test", "yahootestid", "http://example.com/avatar")
}

func (ts *ExternalTestSuite) TestSignupExternalYahooDisableSignupErrorWhenNoUser() {
	ts.Config.DisableSignup = true
	tokenCount, userCount := 0, 0
	code := "authcode"
	server := YahooTestSignupSetup(ts, &tokenCount, &userCount, code, yahooUser)
	defer server.Close()

	u := performAuthorization(ts, "yahoo", code, "")

	assertAuthorizationFailure(ts, u, "Signups not allowed for this instance", "access_denied", "yahoo@example.com")
}

func (ts *ExternalTestSuite) TestSignupExternalYahooDisableSignupErrorWhenNoEmail() {
	ts.Config.DisableSignup = true
	tokenCount, userCount := 0, 0
	code := "authcode"
	server := YahooTestSignupSetup(ts, &tokenCount, &userCount, code, yahooUserNoEmail)
	defer server.Close()

	u := performAuthorization(ts, "yahoo", code, "")

	assertAuthorizationFailure(ts, u, "Error getting user email from external provider", "server_error", "yahoo@example.com")

}

func (ts *ExternalTestSuite) TestSignupExternalYahooDisableSignupSuccessWithPrimaryEmail() {
	ts.Config.DisableSignup = true

	ts.createUser("yahootestid", "yahoo@example.com", "Yahoo Test", "http://example.com/avatar", "")

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := YahooTestSignupSetup(ts, &tokenCount, &userCount, code, yahooUser)
	defer server.Close()

	u := performAuthorization(ts, "yahoo", code, "")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "yahoo@example.com", "Yahoo Test", "yahootestid", "http://example.com/avatar")
}

func (ts *ExternalTestSuite) TestInviteTokenExternalYahooSuccessWhenMatchingToken() {
	// name and avatar should be populated from Yahoo API
	ts.createUser("yahootestid", "yahoo@example.com", "", "http://example.com/avatar", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := YahooTestSignupSetup(ts, &tokenCount, &userCount, code, yahooUser)
	defer server.Close()

	u := performAuthorization(ts, "yahoo", code, "invite_token")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "yahoo@example.com", "Yahoo Test", "yahootestid", "http://example.com/avatar")
}

func (ts *ExternalTestSuite) TestInviteTokenExternalYahooErrorWhenNoMatchingToken() {
	tokenCount, userCount := 0, 0
	code := "authcode"
	yahooUser := `{"name":"Yahoo Test","avatar":{"href":"http://example.com/avatar"}}`
	server := YahooTestSignupSetup(ts, &tokenCount, &userCount, code, yahooUser)
	defer server.Close()

	w := performAuthorizationRequest(ts, "yahoo", "invite_token")
	ts.Require().Equal(http.StatusNotFound, w.Code)
}

func (ts *ExternalTestSuite) TestInviteTokenExternalYahooErrorWhenWrongToken() {
	ts.createUser("yahootestid", "yahoo@example.com", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	yahooUser := `{"name":"Yahoo Test","avatar":{"href":"http://example.com/avatar"}}`
	server := YahooTestSignupSetup(ts, &tokenCount, &userCount, code, yahooUser)
	defer server.Close()

	w := performAuthorizationRequest(ts, "yahoo", "wrong_token")
	ts.Require().Equal(http.StatusNotFound, w.Code)
}

func (ts *ExternalTestSuite) TestInviteTokenExternalYahooErrorWhenEmailDoesntMatch() {
	ts.createUser("yahootestid", "yahoo@example.com", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	yahooUser := `{"name":"Yahoo Test", "email":"other@example.com", "avatar":{"href":"http://example.com/avatar"}}`
	server := YahooTestSignupSetup(ts, &tokenCount, &userCount, code, yahooUser)
	defer server.Close()

	u := performAuthorization(ts, "yahoo", code, "invite_token")

	assertAuthorizationFailure(ts, u, "Invited email does not match emails from external provider", "invalid_request", "")
}
