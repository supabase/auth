package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"

	jwt "github.com/golang-jwt/jwt/v5"
)

const (
	pinterestUser           string = `{"bot":{"owner":{"user":{"id":"pinterestTestId","name":"Pinterest Test","avatar_url":"http://example.com/avatar","person":{"email":"pinterest@example.com"},"verified_email":true}}}}`
	pinterestUserWrongEmail string = `{"bot":{"owner":{"user":{"id":"pinterestTestId","name":"Pinterest Test","avatar_url":"http://example.com/avatar","person":{"email":"other@example.com"},"verified_email":true}}}}`
	pinterestUserNoEmail    string = `{"bot":{"owner":{"user":{"id":"pinterestTestId","name":"Pinterest Test","avatar_url":"http://example.com/avatar","verified_email":true}}}}`
)

func (ts *ExternalTestSuite) TestSignupExternalPinterest() {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/authorize?provider=pinterest", nil)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)
	u, err := url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")
	q := u.Query()
	ts.Equal(ts.Config.External.Pinterest.RedirectURI, q.Get("redirect_uri"))
	ts.Equal(ts.Config.External.Pinterest.ClientID, []string{q.Get("client_id")})
	ts.Equal("code", q.Get("response_type"))

	claims := ExternalProviderClaims{}
	p := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}))
	_, err = p.ParseWithClaims(q.Get("state"), &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(ts.Config.JWT.Secret), nil
	})
	ts.Require().NoError(err)

	ts.Equal("pinterest", claims.Provider)
	ts.Equal(ts.Config.SiteURL, claims.SiteURL)
}

func PinterestTestSignupSetup(ts *ExternalTestSuite, tokenCount *int, userCount *int, code string, user string) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/oauth/token":
			*tokenCount++
			ts.Equal(code, r.FormValue("code"))
			ts.Equal("authorization_code", r.FormValue("grant_type"))
			ts.Equal(ts.Config.External.Pinterest.RedirectURI, r.FormValue("redirect_uri"))

			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"pinterest_token","expires_in":100000}`)
		case "/v1/users/me":
			*userCount++
			ts.Contains(r.Header, "Authorization")
			ts.Contains(r.Header, "Pinterest-Version")
			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, user)
		default:
			w.WriteHeader(500)
			ts.Fail("unknown pinterest oauth call %s", r.URL.Path)
		}
	}))

	ts.Config.External.Pinterest.URL = server.URL

	return server
}

func (ts *ExternalTestSuite) TestSignupExternalPinterest_AuthorizationCode() {
	ts.Config.DisableSignup = false
	tokenCount, userCount := 0, 0
	code := "authcode"
	server := PinterestTestSignupSetup(ts, &tokenCount, &userCount, code, pinterestUser)
	defer server.Close()

	u := performAuthorization(ts, "pinterest", code, "")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "pinterest@example.com", "Pinterest Test", "pinterestTestId", "http://example.com/avatar")
}

func (ts *ExternalTestSuite) TestSignupExternalPinterestDisableSignupErrorWhenNoUser() {
	ts.Config.DisableSignup = true

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := PinterestTestSignupSetup(ts, &tokenCount, &userCount, code, pinterestUser)
	defer server.Close()

	u := performAuthorization(ts, "pinterest", code, "")

	assertAuthorizationFailure(ts, u, "Signups not allowed for this instance", "access_denied", "pinterest@example.com")
}
func (ts *ExternalTestSuite) TestSignupExternalPinterestDisableSignupErrorWhenEmptyEmail() {
	ts.Config.DisableSignup = true

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := PinterestTestSignupSetup(ts, &tokenCount, &userCount, code, pinterestUserNoEmail)
	defer server.Close()

	u := performAuthorization(ts, "pinterest", code, "")

	assertAuthorizationFailure(ts, u, "Error getting user email from external provider", "server_error", "pinterest@example.com")
}

func (ts *ExternalTestSuite) TestSignupExternalPinterestDisableSignupSuccessWithPrimaryEmail() {
	ts.Config.DisableSignup = true

	ts.createUser("pinterestTestId", "pinterest@example.com", "Pinterest Test", "http://example.com/avatar", "")

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := PinterestTestSignupSetup(ts, &tokenCount, &userCount, code, pinterestUser)
	defer server.Close()

	u := performAuthorization(ts, "pinterest", code, "")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "pinterest@example.com", "Pinterest Test", "pinterestTestId", "http://example.com/avatar")
}

func (ts *ExternalTestSuite) TestInviteTokenExternalPinterestSuccessWhenMatchingToken() {
	// name and avatar should be populated from Pinterest API
	ts.createUser("pinterestTestId", "pinterest@example.com", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := PinterestTestSignupSetup(ts, &tokenCount, &userCount, code, pinterestUser)
	defer server.Close()

	u := performAuthorization(ts, "pinterest", code, "invite_token")

	fmt.Printf("%+v\n", u)

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "pinterest@example.com", "Pinterest Test", "pinterestTestId", "http://example.com/avatar")
}

func (ts *ExternalTestSuite) TestInviteTokenExternalPinterestErrorWhenNoMatchingToken() {
	tokenCount, userCount := 0, 0
	code := "authcode"
	server := PinterestTestSignupSetup(ts, &tokenCount, &userCount, code, pinterestUser)
	defer server.Close()

	w := performAuthorizationRequest(ts, "pinterest", "invite_token")
	ts.Require().Equal(http.StatusNotFound, w.Code)
}

func (ts *ExternalTestSuite) TestInviteTokenExternalPinterestErrorWhenWrongToken() {
	ts.createUser("pinterestTestId", "pinterest@example.com", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := PinterestTestSignupSetup(ts, &tokenCount, &userCount, code, pinterestUser)
	defer server.Close()

	w := performAuthorizationRequest(ts, "pinterest", "wrong_token")
	ts.Require().Equal(http.StatusNotFound, w.Code)
}

func (ts *ExternalTestSuite) TestInviteTokenExternalPinterestErrorWhenEmailDoesntMatch() {
	ts.createUser("pinterestTestId", "pinterest@example.com", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := PinterestTestSignupSetup(ts, &tokenCount, &userCount, code, pinterestUserWrongEmail)
	defer server.Close()

	u := performAuthorization(ts, "pinterest", code, "invite_token")

	assertAuthorizationFailure(ts, u, "Invited email does not match emails from external provider", "invalid_request", "")
}
