package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/supabase/auth/internal/models"
)

const (
	nhsCIS2User           string = `{"sub": "nhscis2testid", "name": "Dr John Smith", "given_name": "John", "family_name": "Smith", "email": "john.smith@nhs.net", "preferred_username": "jsmith", "email_verified": true, "uid": "123456789012", "nhsid_nrbac_roles": "R8000:G8000:R8001", "id_assurance_level": "3"}`
	nhsCIS2UserNoEmail    string = `{"sub": "nhscis2testid", "name": "Dr John Smith", "preferred_username": "jsmith", "email_verified": false}`
	nhsCIS2UserUnverified string = `{"sub": "nhscis2testid", "name": "Dr Jane Doe", "email": "jane.doe@nhs.net", "email_verified": false}`
)

func (ts *ExternalTestSuite) TestSignupExternalNHSCIS2() {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/authorize?provider=nhs_cis2", nil)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)
	u, err := url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")
	q := u.Query()
	ts.Equal(ts.Config.External.NHSCIS2.RedirectURI, q.Get("redirect_uri"))
	ts.Equal(ts.Config.External.NHSCIS2.ClientID, []string{q.Get("client_id")})
	ts.Equal("code", q.Get("response_type"))
	ts.Equal("openid profile email", q.Get("scope"))

	claims := ExternalProviderClaims{}
	p := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}))
	_, err = p.ParseWithClaims(q.Get("state"), &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(ts.Config.JWT.Secret), nil
	})
	ts.Require().NoError(err)

	ts.Equal("nhs_cis2", claims.Provider)
	ts.Equal(ts.Config.SiteURL, claims.SiteURL)
}

func NHSCIS2TestSignupSetup(ts *ExternalTestSuite, tokenCount *int, userCount *int, code string, user string) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openam/oauth2/realms/root/realms/NHSIdentity/realms/Healthcare/access_token":
			*tokenCount++
			ts.Equal(code, r.FormValue("code"))
			ts.Equal("authorization_code", r.FormValue("grant_type"))
			ts.Equal(ts.Config.External.NHSCIS2.RedirectURI, r.FormValue("redirect_uri"))

			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"nhs_cis2_token","expires_in":100000}`)
		case "/openam/oauth2/realms/root/realms/NHSIdentity/realms/Healthcare/userinfo":
			*userCount++
			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, user)
		default:
			w.WriteHeader(500)
			ts.Fail("unknown NHS CIS2 oauth call %s", r.URL.Path)
		}
	}))

	ts.Config.External.NHSCIS2.URL = server.URL

	return server
}

func (ts *ExternalTestSuite) TestSignupExternalNHSCIS2WithoutURLSetup() {
	ts.createUser("nhscis2testid", "john.smith@nhs.net", "Dr John Smith", "", "")
	tokenCount, userCount := 0, 0
	code := "authcode"
	server := NHSCIS2TestSignupSetup(ts, &tokenCount, &userCount, code, nhsCIS2User)
	ts.Config.External.NHSCIS2.URL = ""
	defer server.Close()

	w := performAuthorizationRequest(ts, "nhs_cis2", code)
	ts.Equal(w.Code, http.StatusBadRequest)
}

func (ts *ExternalTestSuite) TestSignupExternalNHSCIS2_AuthorizationCode() {
	ts.Config.DisableSignup = false
	ts.createUser("nhscis2testid", "john.smith@nhs.net", "Dr John Smith", "", "")
	tokenCount, userCount := 0, 0
	code := "authcode"
	server := NHSCIS2TestSignupSetup(ts, &tokenCount, &userCount, code, nhsCIS2User)
	defer server.Close()

	u := performAuthorization(ts, "nhs_cis2", code, "")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "john.smith@nhs.net", "Dr John Smith", "nhscis2testid", "")
}

func (ts *ExternalTestSuite) TestSignupExternalNHSCIS2DisableSignupErrorWhenNoUser() {
	ts.Config.DisableSignup = true
	tokenCount, userCount := 0, 0
	code := "authcode"
	server := NHSCIS2TestSignupSetup(ts, &tokenCount, &userCount, code, nhsCIS2User)
	defer server.Close()

	u := performAuthorization(ts, "nhs_cis2", code, "")

	assertAuthorizationFailure(ts, u, "Signups not allowed for this instance", "access_denied", "john.smith@nhs.net")
}

func (ts *ExternalTestSuite) TestSignupExternalNHSCIS2DisableSignupErrorWhenNoEmail() {
	ts.Config.DisableSignup = true
	tokenCount, userCount := 0, 0
	code := "authcode"
	server := NHSCIS2TestSignupSetup(ts, &tokenCount, &userCount, code, nhsCIS2UserNoEmail)
	defer server.Close()

	u := performAuthorization(ts, "nhs_cis2", code, "")

	assertAuthorizationFailure(ts, u, "Error getting user email from external provider", "server_error", "john.smith@nhs.net")
}

func (ts *ExternalTestSuite) TestSignupExternalNHSCIS2DisableSignupSuccessWithPrimaryEmail() {
	ts.Config.DisableSignup = true

	ts.createUser("nhscis2testid", "john.smith@nhs.net", "Dr John Smith", "", "")

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := NHSCIS2TestSignupSetup(ts, &tokenCount, &userCount, code, nhsCIS2User)
	defer server.Close()

	u := performAuthorization(ts, "nhs_cis2", code, "")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "john.smith@nhs.net", "Dr John Smith", "nhscis2testid", "")
}

func (ts *ExternalTestSuite) TestInviteTokenExternalNHSCIS2SuccessWhenMatchingToken() {
	// name should be populated from NHS CIS2 API
	ts.createUser("nhscis2testid", "john.smith@nhs.net", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := NHSCIS2TestSignupSetup(ts, &tokenCount, &userCount, code, nhsCIS2User)
	defer server.Close()

	u := performAuthorization(ts, "nhs_cis2", code, "invite_token")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "john.smith@nhs.net", "Dr John Smith", "nhscis2testid", "")
}

func (ts *ExternalTestSuite) TestInviteTokenExternalNHSCIS2ErrorWhenNoMatchingToken() {
	tokenCount, userCount := 0, 0
	code := "authcode"
	nhsCIS2UserData := `{"name":"Dr John Smith"}`
	server := NHSCIS2TestSignupSetup(ts, &tokenCount, &userCount, code, nhsCIS2UserData)
	defer server.Close()

	w := performAuthorizationRequest(ts, "nhs_cis2", "invite_token")
	ts.Require().Equal(http.StatusNotFound, w.Code)
}

func (ts *ExternalTestSuite) TestInviteTokenExternalNHSCIS2ErrorWhenWrongToken() {
	ts.createUser("nhscis2testid", "john.smith@nhs.net", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	nhsCIS2UserData := `{"name":"Dr John Smith"}`
	server := NHSCIS2TestSignupSetup(ts, &tokenCount, &userCount, code, nhsCIS2UserData)
	defer server.Close()

	w := performAuthorizationRequest(ts, "nhs_cis2", "wrong_token")
	ts.Require().Equal(http.StatusNotFound, w.Code)
}

func (ts *ExternalTestSuite) TestInviteTokenExternalNHSCIS2ErrorWhenEmailDoesntMatch() {
	ts.createUser("nhscis2testid", "john.smith@nhs.net", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	nhsCIS2UserData := `{"name":"Dr Jane Doe", "email":"other@nhs.net"}`
	server := NHSCIS2TestSignupSetup(ts, &tokenCount, &userCount, code, nhsCIS2UserData)
	defer server.Close()

	u := performAuthorization(ts, "nhs_cis2", code, "invite_token")

	assertAuthorizationFailure(ts, u, "Invited email does not match emails from external provider", "invalid_request", "")
}

func (ts *ExternalTestSuite) TestSignupExternalNHSCIS2WithCustomScopes() {
	// Test that custom scopes are properly appended
	req := httptest.NewRequest(http.MethodGet, "http://localhost/authorize?provider=nhs_cis2&scopes=nationalrbacaccess,associatedorgs", nil)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)
	u, err := url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")
	q := u.Query()
	scope := q.Get("scope")
	ts.Contains(scope, "openid")
	ts.Contains(scope, "profile")
	ts.Contains(scope, "email")
	ts.Contains(scope, "nationalrbacaccess")
	ts.Contains(scope, "associatedorgs")
}

func (ts *ExternalTestSuite) TestSignupExternalNHSCIS2_PreservesNHSClaims() {
	ts.Config.DisableSignup = false
	tokenCount, userCount := 0, 0
	code := "authcode"
	server := NHSCIS2TestSignupSetup(ts, &tokenCount, &userCount, code, nhsCIS2User)
	defer server.Close()

	u := performAuthorization(ts, "nhs_cis2", code, "")

	// Verify authorization was successful
	v, err := url.ParseQuery(u.RawQuery)
	ts.Require().NoError(err)
	ts.Require().Empty(v.Get("error_description"))
	ts.Require().Empty(v.Get("error"))

	// Check that user was created with NHS-specific metadata
	user, err := models.FindUserByEmailAndAudience(ts.API.db, "john.smith@nhs.net", ts.Config.JWT.Aud)
	ts.Require().NoError(err)
	ts.NotNil(user)
	ts.Equal("nhscis2testid", user.UserMetaData["provider_id"])
	ts.Equal("Dr John Smith", user.UserMetaData["full_name"])
}
