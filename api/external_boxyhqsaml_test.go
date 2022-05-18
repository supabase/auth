package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"

	jwt "github.com/golang-jwt/jwt"
)

const (
	boxyhqsamlUser           string = `{"id":"test_prof_boxyhqsaml","first_name":"John","last_name":"Doe","email":"boxyhqsaml@example.com","connection_id":"test_conn_1","organization_id":"test_org_1","connection_type":"test","idp_id":"test_idp_1","object": "profile","raw_attributes": {}}`
	boxyhqsamlUserWrongEmail string = `{"id":"test_prof_boxyhqsaml","first_name":"John","last_name":"Doe","email":"other@example.com","connection_id":"test_conn_1","organization_id":"test_org_1","connection_type":"test","idp_id":"test_idp_1","object": "profile","raw_attributes": {}}`
	boxyhqsamlUserNoEmail    string = `{"id":"test_prof_boxyhqsaml","first_name":"John","last_name":"Doe","connection_id":"test_conn_1","organization_id":"test_org_1","connection_type":"test","idp_id":"test_idp_1","object": "profile","raw_attributes": {}}`
)

func (ts *ExternalTestSuite) TestSignupExternalBoxyhqSaml() {
	scopes := url.Values{}
	scopes.Add("tenant", "acme.com")
	scopes.Add("product", "crm")
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("http://localhost/authorize?provider=boxyhqsaml&scopes=%s", url.QueryEscape(scopes.Encode())), nil)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)
	u, err := url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")
	ts.Equal(ts.Config.External.BoxyHQSAML.URL, u.Scheme+"://"+u.Host)
	q := u.Query()
	ts.Equal(ts.Config.External.BoxyHQSAML.RedirectURI, q.Get("redirect_uri"))
	ts.Equal(ts.Config.External.BoxyHQSAML.ClientID, q.Get("client_id"))
	ts.Equal("code", q.Get("response_type"))
	ts.Equal("product=crm&tenant=acme.com", q.Get("scope"))

	claims := ExternalProviderClaims{}
	p := jwt.Parser{ValidMethods: []string{jwt.SigningMethodHS256.Name}}
	_, err = p.ParseWithClaims(q.Get("state"), &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(ts.Config.JWT.Secret), nil
	})
	ts.Require().NoError(err)

	ts.Equal("boxyhqsaml", claims.Provider)
	ts.Equal(ts.Config.SiteURL, claims.SiteURL)
}

func BoxyHQSAMLTestSignupSetup(ts *ExternalTestSuite, tokenCount *int, userCount *int, code string, user string) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/oauth/token":
			*tokenCount++
			ts.Equal(code, r.FormValue("code"))
			ts.Equal("authorization_code", r.FormValue("grant_type"))
			ts.Equal(ts.Config.External.BoxyHQSAML.RedirectURI, r.FormValue("redirect_uri"))

			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"boxyhqsaml_token","expires_in":300}`)
		case "/api/oauth/userinfo":
			*userCount++
			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, user)
		default:
			w.WriteHeader(500)
			ts.Fail("unknown boxyhqsaml oauth call %s", r.URL.Path)
		}
	}))

	ts.Config.External.BoxyHQSAML.URL = server.URL

	return server
}

func (ts *ExternalTestSuite) TestSignupExternalBoxyHQSAML_AuthorizationCode() {
	ts.Config.DisableSignup = false
	tokenCount, userCount := 0, 0
	code := "authcode"
	server := BoxyHQSAMLTestSignupSetup(ts, &tokenCount, &userCount, code, boxyhqsamlUser)
	defer server.Close()

	u := performAuthorization(ts, "boxyhqsaml", code, "")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "boxyhqsaml@example.com", "BoxyHQSAML Test", "boxyhqsamlTestId", "")
}

func (ts *ExternalTestSuite) TestSignupExternalBoxyHQSAMLDisableSignupErrorWhenNoUser() {
	ts.Config.DisableSignup = true

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := BoxyHQSAMLTestSignupSetup(ts, &tokenCount, &userCount, code, boxyhqsamlUser)
	defer server.Close()

	u := performAuthorization(ts, "boxyhqsaml", code, "")

	assertAuthorizationFailure(ts, u, "Signups not allowed for this instance", "access_denied", "boxyhqsaml@example.com")
}
func (ts *ExternalTestSuite) TestSignupExternalBoxyHQSAMLDisableSignupErrorWhenEmptyEmail() {
	ts.Config.DisableSignup = true

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := BoxyHQSAMLTestSignupSetup(ts, &tokenCount, &userCount, code, boxyhqsamlUserNoEmail)
	defer server.Close()

	u := performAuthorization(ts, "boxyhqsaml", code, "")

	assertAuthorizationFailure(ts, u, "Error getting user email from external provider", "server_error", "boxyhqsaml@example.com")
}

func (ts *ExternalTestSuite) TestSignupExternalBoxyHQSAMLDisableSignupSuccessWithPrimaryEmail() {
	ts.Config.DisableSignup = true

	ts.createUser("boxyhqsamlTestId", "boxyhqsaml@example.com", "BoxyHQSAML Test", "http://example.com/avatar", "")

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := BoxyHQSAMLTestSignupSetup(ts, &tokenCount, &userCount, code, boxyhqsamlUser)
	defer server.Close()

	u := performAuthorization(ts, "boxyhqsaml", code, "")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "boxyhqsaml@example.com", "BoxyHQSAML Test", "boxyhqsamlTestId", "http://example.com/avatar")
}

func (ts *ExternalTestSuite) TestInviteTokenExternalBoxyHQSAMLSuccessWhenMatchingToken() {
	// name and avatar should be populated from BoxyHQSAML API
	ts.createUser("boxyhqsamlTestId", "boxyhqsaml@example.com", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := BoxyHQSAMLTestSignupSetup(ts, &tokenCount, &userCount, code, boxyhqsamlUser)
	defer server.Close()

	u := performAuthorization(ts, "boxyhqsaml", code, "invite_token")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "boxyhqsaml@example.com", "BoxyHQSAML Test", "boxyhqsamlTestId", "http://example.com/avatar")
}

func (ts *ExternalTestSuite) TestInviteTokenExternalBoxyHQSAMLErrorWhenNoMatchingToken() {
	tokenCount, userCount := 0, 0
	code := "authcode"
	server := BoxyHQSAMLTestSignupSetup(ts, &tokenCount, &userCount, code, boxyhqsamlUser)
	defer server.Close()

	w := performAuthorizationRequest(ts, "boxyhqsaml", "invite_token")
	ts.Require().Equal(http.StatusNotFound, w.Code)
}

func (ts *ExternalTestSuite) TestInviteTokenExternalBoxyHQSAMLErrorWhenWrongToken() {
	ts.createUser("boxyhqsamlTestId", "boxyhqsaml@example.com", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := BoxyHQSAMLTestSignupSetup(ts, &tokenCount, &userCount, code, boxyhqsamlUser)
	defer server.Close()

	w := performAuthorizationRequest(ts, "boxyhqsaml", "wrong_token")
	ts.Require().Equal(http.StatusNotFound, w.Code)
}

func (ts *ExternalTestSuite) TestInviteTokenExternalBoxyHQSAMLErrorWhenEmailDoesntMatch() {
	ts.createUser("boxyhqsamlTestId", "boxyhqsaml@example.com", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := BoxyHQSAMLTestSignupSetup(ts, &tokenCount, &userCount, code, boxyhqsamlUserWrongEmail)
	defer server.Close()

	u := performAuthorization(ts, "boxyhqsaml", code, "invite_token")

	assertAuthorizationFailure(ts, u, "Invited email does not match emails from external provider", "invalid_request", "")
}
