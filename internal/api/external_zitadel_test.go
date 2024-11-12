package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"

	jwt "github.com/golang-jwt/jwt/v5"
)

const (
	zidadelUser        string = `{"sub": "zidadeltestid", "name": "Zidadel Test", "email": "zidadel@example.com", "preferred_username": "zidadel", "email_verified": true}`
	zidadelUserNoEmail string = `{"sub": "zidadeltestid", "name": "Zidadel Test", "preferred_username": "zidadel", "email_verified": false}`
)

func (ts *ExternalTestSuite) TestSignupExternalZidadel() {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/authorize?provider=zidadel", nil)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)
	u, err := url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")
	q := u.Query()
	ts.Equal(ts.Config.External.Zidadel.RedirectURI, q.Get("redirect_uri"))
	ts.Equal(ts.Config.External.Zidadel.ClientID, []string{q.Get("client_id")})
	ts.Equal("code", q.Get("response_type"))
	ts.Equal("profile email", q.Get("scope"))

	claims := ExternalProviderClaims{}
	p := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}))
	_, err = p.ParseWithClaims(q.Get("state"), &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(ts.Config.JWT.Secret), nil
	})
	ts.Require().NoError(err)

	ts.Equal("zidadel", claims.Provider)
	ts.Equal(ts.Config.SiteURL, claims.SiteURL)
}

func ZidadelTestSignupSetup(ts *ExternalTestSuite, tokenCount *int, userCount *int, code string, user string) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/v2/token":
			*tokenCount++
			ts.Equal(code, r.FormValue("code"))
			ts.Equal("authorization_code", r.FormValue("grant_type"))
			ts.Equal(ts.Config.External.Zidadel.RedirectURI, r.FormValue("redirect_uri"))

			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"zidadel_token","expires_in":100000}`)
		case "/oidc/v1/userinfo":
			*userCount++
			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, user)
		default:
			w.WriteHeader(500)
			ts.Fail("unknown zidadel oauth call %s", r.URL.Path)
		}
	}))

	ts.Config.External.Zidadel.URL = server.URL

	return server
}

func (ts *ExternalTestSuite) TestSignupExternalZidadelWithoutURLSetup() {
	ts.createUser("zidadeltestid", "zidadel@example.com", "Zidadel Test", "", "")
	tokenCount, userCount := 0, 0
	code := "authcode"
	server := ZidadelTestSignupSetup(ts, &tokenCount, &userCount, code, zidadelUser)
	ts.Config.External.Zidadel.URL = ""
	defer server.Close()

	w := performAuthorizationRequest(ts, "zidadel", code)
	ts.Equal(w.Code, http.StatusBadRequest)
}

func (ts *ExternalTestSuite) TestSignupExternalZidadel_AuthorizationCode() {
	ts.Config.DisableSignup = false
	ts.createUser("zidadeltestid", "zidadel@example.com", "Zidadel Test", "", "")
	tokenCount, userCount := 0, 0
	code := "authcode"
	server := ZidadelTestSignupSetup(ts, &tokenCount, &userCount, code, zidadelUser)
	defer server.Close()

	u := performAuthorization(ts, "zidadel", code, "")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "zidadel@example.com", "Zidadel Test", "zidadeltestid", "")
}

func (ts *ExternalTestSuite) TestSignupExternalZidadelDisableSignupErrorWhenNoUser() {
	ts.Config.DisableSignup = true
	tokenCount, userCount := 0, 0
	code := "authcode"
	server := ZidadelTestSignupSetup(ts, &tokenCount, &userCount, code, zidadelUser)
	defer server.Close()

	u := performAuthorization(ts, "zidadel", code, "")

	assertAuthorizationFailure(ts, u, "Signups not allowed for this instance", "access_denied", "zidadel@example.com")
}

func (ts *ExternalTestSuite) TestSignupExternalZidadelDisableSignupErrorWhenNoEmail() {
	ts.Config.DisableSignup = true
	tokenCount, userCount := 0, 0
	code := "authcode"
	server := ZidadelTestSignupSetup(ts, &tokenCount, &userCount, code, zidadelUserNoEmail)
	defer server.Close()

	u := performAuthorization(ts, "zidadel", code, "")

	assertAuthorizationFailure(ts, u, "Error getting user email from external provider", "server_error", "zidadel@example.com")

}

func (ts *ExternalTestSuite) TestSignupExternalZidadelDisableSignupSuccessWithPrimaryEmail() {
	ts.Config.DisableSignup = true

	ts.createUser("zidadeltestid", "zidadel@example.com", "Zidadel Test", "", "")

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := ZidadelTestSignupSetup(ts, &tokenCount, &userCount, code, zidadelUser)
	defer server.Close()

	u := performAuthorization(ts, "zidadel", code, "")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "zidadel@example.com", "Zidadel Test", "zidadeltestid", "")
}

func (ts *ExternalTestSuite) TestInviteTokenExternalZidadelSuccessWhenMatchingToken() {
	// name and avatar should be populated from Zidadel API
	ts.createUser("zidadeltestid", "zidadel@example.com", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := ZidadelTestSignupSetup(ts, &tokenCount, &userCount, code, zidadelUser)
	defer server.Close()

	u := performAuthorization(ts, "zidadel", code, "invite_token")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "zidadel@example.com", "Zidadel Test", "zidadeltestid", "")
}

func (ts *ExternalTestSuite) TestInviteTokenExternalZidadelErrorWhenNoMatchingToken() {
	tokenCount, userCount := 0, 0
	code := "authcode"
	zidadelUser := `{"name":"Zidadel Test","avatar":{"href":"http://example.com/avatar"}}`
	server := ZidadelTestSignupSetup(ts, &tokenCount, &userCount, code, zidadelUser)
	defer server.Close()

	w := performAuthorizationRequest(ts, "zidadel", "invite_token")
	ts.Require().Equal(http.StatusNotFound, w.Code)
}

func (ts *ExternalTestSuite) TestInviteTokenExternalZidadelErrorWhenWrongToken() {
	ts.createUser("zidadeltestid", "zidadel@example.com", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	zidadelUser := `{"name":"Zidadel Test","avatar":{"href":"http://example.com/avatar"}}`
	server := ZidadelTestSignupSetup(ts, &tokenCount, &userCount, code, zidadelUser)
	defer server.Close()

	w := performAuthorizationRequest(ts, "zidadel", "wrong_token")
	ts.Require().Equal(http.StatusNotFound, w.Code)
}

func (ts *ExternalTestSuite) TestInviteTokenExternalZidadelErrorWhenEmailDoesntMatch() {
	ts.createUser("zidadeltestid", "zidadel@example.com", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	zidadelUser := `{"name":"Zidadel Test", "email":"other@example.com", "avatar":{"href":"http://example.com/avatar"}}`
	server := ZidadelTestSignupSetup(ts, &tokenCount, &userCount, code, zidadelUser)
	defer server.Close()

	u := performAuthorization(ts, "zidadel", code, "invite_token")

	assertAuthorizationFailure(ts, u, "Invited email does not match emails from external provider", "invalid_request", "")
}
