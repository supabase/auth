package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
)

const (
	zitadelUser        string = `{"sub": "zitadeltestid", "name": "Zitadel Test", "email": "zitadel@example.com", "preferred_username": "zitadel", "email_verified": true}`
	zitadelUserNoEmail string = `{"sub": "zitadeltestid", "name": "Zitadel Test", "preferred_username": "zitadel", "email_verified": false}`
)

func (ts *ExternalTestSuite) TestSignupExternalZitadel() {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/authorize?provider=zitadel", nil)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)
	u, err := url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")
	q := u.Query()
	ts.Equal(ts.Config.External.Zitadel.RedirectURI, q.Get("redirect_uri"))
	ts.Equal(ts.Config.External.Zitadel.ClientID, []string{q.Get("client_id")})
	ts.Equal("code", q.Get("response_type"))
	ts.Equal("profile email", q.Get("scope"))

	assertValidOAuthState(ts, q.Get("state"), "zitadel")
}

func ZitadelTestSignupSetup(ts *ExternalTestSuite, tokenCount *int, userCount *int, code string, user string) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/v2/token":
			*tokenCount++
			ts.Equal(code, r.FormValue("code"))
			ts.Equal("authorization_code", r.FormValue("grant_type"))
			ts.Equal(ts.Config.External.Zitadel.RedirectURI, r.FormValue("redirect_uri"))

			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"zitadel_token","expires_in":100000}`)
		case "/oidc/v1/userinfo":
			*userCount++
			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, user)
		default:
			w.WriteHeader(500)
			ts.Fail("unknown zitadel oauth call %s", r.URL.Path)
		}
	}))

	ts.Config.External.Zitadel.URL = server.URL

	return server
}

func (ts *ExternalTestSuite) TestSignupExternalZitadelWithoutURLSetup() {
	ts.createUser("zitadeltestid", "zitadel@example.com", "Zitadel Test", "", "")
	tokenCount, userCount := 0, 0
	code := "authcode"
	server := ZitadelTestSignupSetup(ts, &tokenCount, &userCount, code, zitadelUser)
	ts.Config.External.Zitadel.URL = ""
	defer server.Close()

	w := performAuthorizationRequest(ts, "zitadel", code)
	ts.Equal(w.Code, http.StatusBadRequest)
}

func (ts *ExternalTestSuite) TestSignupExternalZitadel_AuthorizationCode() {
	ts.Config.DisableSignup = false
	ts.createUser("zitadeltestid", "zitadel@example.com", "Zitadel Test", "", "")
	tokenCount, userCount := 0, 0
	code := "authcode"
	server := ZitadelTestSignupSetup(ts, &tokenCount, &userCount, code, zitadelUser)
	defer server.Close()

	u := performAuthorization(ts, "zitadel", code, "")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "zitadel@example.com", "Zitadel Test", "zitadeltestid", "")
}

func (ts *ExternalTestSuite) TestSignupExternalZitadelDisableSignupErrorWhenNoUser() {
	ts.Config.DisableSignup = true
	tokenCount, userCount := 0, 0
	code := "authcode"
	server := ZitadelTestSignupSetup(ts, &tokenCount, &userCount, code, zitadelUser)
	defer server.Close()

	u := performAuthorization(ts, "zitadel", code, "")

	assertAuthorizationFailure(ts, u, "Signups not allowed for this instance", "access_denied", "zitadel@example.com")
}

func (ts *ExternalTestSuite) TestSignupExternalZitadelDisableSignupErrorWhenNoEmail() {
	ts.Config.DisableSignup = true
	tokenCount, userCount := 0, 0
	code := "authcode"
	server := ZitadelTestSignupSetup(ts, &tokenCount, &userCount, code, zitadelUserNoEmail)
	defer server.Close()

	u := performAuthorization(ts, "zitadel", code, "")

	assertAuthorizationFailure(ts, u, "Error getting user email from external provider", "server_error", "zitadel@example.com")
}

func (ts *ExternalTestSuite) TestSignupExternalZitadelDisableSignupSuccessWithPrimaryEmail() {
	ts.Config.DisableSignup = true

	ts.createUser("zitadeltestid", "zitadel@example.com", "Zitadel Test", "", "")

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := ZitadelTestSignupSetup(ts, &tokenCount, &userCount, code, zitadelUser)
	defer server.Close()

	u := performAuthorization(ts, "zitadel", code, "")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "zitadel@example.com", "Zitadel Test", "zitadeltestid", "")
}

func (ts *ExternalTestSuite) TestInviteTokenExternalZitadelSuccessWhenMatchingToken() {
	// name and avatar should be populated from Zitadel API
	ts.createUser("zitadeltestid", "zitadel@example.com", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := ZitadelTestSignupSetup(ts, &tokenCount, &userCount, code, zitadelUser)
	defer server.Close()

	u := performAuthorization(ts, "zitadel", code, "invite_token")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "zitadel@example.com", "Zitadel Test", "zitadeltestid", "")
}

func (ts *ExternalTestSuite) TestInviteTokenExternalZitadelErrorWhenNoMatchingToken() {
	tokenCount, userCount := 0, 0
	code := "authcode"
	zitadelUser := `{"name":"Zitadel Test","avatar":{"href":"http://example.com/avatar"}}`
	server := ZitadelTestSignupSetup(ts, &tokenCount, &userCount, code, zitadelUser)
	defer server.Close()

	w := performAuthorizationRequest(ts, "zitadel", "invite_token")
	ts.Require().Equal(http.StatusNotFound, w.Code)
}

func (ts *ExternalTestSuite) TestInviteTokenExternalZitadelErrorWhenWrongToken() {
	ts.createUser("zitadeltestid", "zitadel@example.com", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	zitadelUser := `{"name":"Zitadel Test","avatar":{"href":"http://example.com/avatar"}}`
	server := ZitadelTestSignupSetup(ts, &tokenCount, &userCount, code, zitadelUser)
	defer server.Close()

	w := performAuthorizationRequest(ts, "zitadel", "wrong_token")
	ts.Require().Equal(http.StatusNotFound, w.Code)
}

func (ts *ExternalTestSuite) TestInviteTokenExternalZitadelErrorWhenEmailDoesntMatch() {
	ts.createUser("zitadeltestid", "zitadel@example.com", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	zitadelUser := `{"name":"Zitadel Test", "email":"other@example.com", "avatar":{"href":"http://example.com/avatar"}}`
	server := ZitadelTestSignupSetup(ts, &tokenCount, &userCount, code, zitadelUser)
	defer server.Close()

	u := performAuthorization(ts, "zitadel", code, "invite_token")

	assertAuthorizationFailure(ts, u, "Invited email does not match emails from external provider", "invalid_request", "")
}
