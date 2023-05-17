package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"

	jwt "github.com/golang-jwt/jwt"
)

const (
	microsoftUser        string = `{"name":"Microsoft Test","email":"microsoft@example.com","sub":"microsofttestid"}`
	microsoftUserNoEmail string = `{"name":"Microsoft Test","sub":"microsofttestid"}`
)

func (ts *ExternalTestSuite) TestSignupExternalMicrosoft() {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/authorize?provider=microsoft", nil)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)
	u, err := url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")
	q := u.Query()
	ts.Equal(ts.Config.External.Microsoft.RedirectURI, q.Get("redirect_uri"))
	ts.Equal(ts.Config.External.Microsoft.ClientID, q.Get("client_id"))
	ts.Equal("code", q.Get("response_type"))
	ts.Equal("openid", q.Get("scope"))

	claims := ExternalProviderClaims{}
	p := jwt.Parser{ValidMethods: []string{jwt.SigningMethodHS256.Name}}
	_, err = p.ParseWithClaims(q.Get("state"), &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(ts.Config.JWT.Secret), nil
	})
	ts.Require().NoError(err)

	ts.Equal("microsoft", claims.Provider)
	ts.Equal(ts.Config.SiteURL, claims.SiteURL)
}

func MicrosoftTestSignupSetup(ts *ExternalTestSuite, tokenCount *int, userCount *int, code string, user string) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2/v2.0/token":
			*tokenCount++
			ts.Equal(code, r.FormValue("code"))
			ts.Equal("authorization_code", r.FormValue("grant_type"))
			ts.Equal(ts.Config.External.Microsoft.RedirectURI, r.FormValue("redirect_uri"))

			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"microsoft_token","expires_in":100000}`)
		case "/oidc/userinfo":
			*userCount++
			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, user)
		default:
			w.WriteHeader(500)
			ts.Fail("unknown microsoft oauth call %s", r.URL.Path)
		}
	}))

	ts.Config.External.Microsoft.URL = server.URL
	ts.Config.External.Microsoft.ApiURL = server.URL

	return server
}

func (ts *ExternalTestSuite) TestSignupExternalMicrosoft_AuthorizationCode() {
	ts.Config.DisableSignup = false
	tokenCount, userCount := 0, 0
	code := "authcode"
	server := MicrosoftTestSignupSetup(ts, &tokenCount, &userCount, code, microsoftUser)
	defer server.Close()

	u := performAuthorization(ts, "microsoft", code, "")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "microsoft@example.com", "Microsoft Test", "microsofttestid", "")
}

func (ts *ExternalTestSuite) TestSignupExternalMicrosoftDisableSignupErrorWhenNoUser() {
	ts.Config.DisableSignup = true
	tokenCount, userCount := 0, 0
	code := "authcode"
	server := MicrosoftTestSignupSetup(ts, &tokenCount, &userCount, code, microsoftUser)
	defer server.Close()

	u := performAuthorization(ts, "microsoft", code, "")

	assertAuthorizationFailure(ts, u, "Signups not allowed for this instance", "access_denied", "microsoft@example.com")
}

func (ts *ExternalTestSuite) TestSignupExternalMicrosoftDisableSignupErrorWhenNoEmail() {
	ts.Config.DisableSignup = true
	tokenCount, userCount := 0, 0
	code := "authcode"
	server := MicrosoftTestSignupSetup(ts, &tokenCount, &userCount, code, microsoftUserNoEmail)
	defer server.Close()

	u := performAuthorization(ts, "microsoft", code, "")

	assertAuthorizationFailure(ts, u, "Error getting user email from external provider", "server_error", "microsoft@example.com")

}

func (ts *ExternalTestSuite) TestSignupExternalMicrosoftDisableSignupSuccessWithPrimaryEmail() {
	ts.Config.DisableSignup = true

	ts.createUser("microsofttestid", "microsoft@example.com", "Microsoft Test", "http://example.com/avatar", "")

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := MicrosoftTestSignupSetup(ts, &tokenCount, &userCount, code, microsoftUser)
	defer server.Close()

	u := performAuthorization(ts, "microsoft", code, "")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "microsoft@example.com", "Microsoft Test", "microsofttestid", "http://example.com/avatar")
}

func (ts *ExternalTestSuite) TestInviteTokenExternalMicrosoftSuccessWhenMatchingToken() {
	// name should be populated from Microsoft API
	ts.createUser("microsofttestid", "microsoft@example.com", "", "http://example.com/avatar", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := MicrosoftTestSignupSetup(ts, &tokenCount, &userCount, code, microsoftUser)
	defer server.Close()

	u := performAuthorization(ts, "microsoft", code, "invite_token")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "microsoft@example.com", "Microsoft Test", "microsofttestid", "http://example.com/avatar")
}

func (ts *ExternalTestSuite) TestInviteTokenExternalMicrosoftErrorWhenNoMatchingToken() {
	tokenCount, userCount := 0, 0
	code := "authcode"
	microsoftUser := `{"name":"Microsoft Test","avatar":{"href":"http://example.com/avatar"}}`
	server := MicrosoftTestSignupSetup(ts, &tokenCount, &userCount, code, microsoftUser)
	defer server.Close()

	w := performAuthorizationRequest(ts, "microsoft", "invite_token")
	ts.Require().Equal(http.StatusNotFound, w.Code)
}

func (ts *ExternalTestSuite) TestInviteTokenExternalMicrosoftErrorWhenWrongToken() {
	ts.createUser("microsofttestid", "microsoft@example.com", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	microsoftUser := `{"name":"Microsoft Test","avatar":{"href":"http://example.com/avatar"}}`
	server := MicrosoftTestSignupSetup(ts, &tokenCount, &userCount, code, microsoftUser)
	defer server.Close()

	w := performAuthorizationRequest(ts, "microsoft", "wrong_token")
	ts.Require().Equal(http.StatusNotFound, w.Code)
}

func (ts *ExternalTestSuite) TestInviteTokenExternalMicrosoftErrorWhenEmailDoesntMatch() {
	ts.createUser("microsofttestid", "microsoft@example.com", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	microsoftUser := `{"name":"Microsoft Test", "email":"other@example.com", "avatar":{"href":"http://example.com/avatar"}}`
	server := MicrosoftTestSignupSetup(ts, &tokenCount, &userCount, code, microsoftUser)
	defer server.Close()

	u := performAuthorization(ts, "microsoft", code, "invite_token")

	assertAuthorizationFailure(ts, u, "Invited email does not match emails from external provider", "invalid_request", "")
}
