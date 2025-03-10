package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"

	jwt "github.com/golang-jwt/jwt/v5"
)

const (
	nextcloudUser           string = `{"ocs":{"data":{"additional_mail":["another@example.com"],"additional_mailScope":["v2-private"],"displayname":"Nextcloud Test","displaynameScope":"v2-private","email":"nextcloud@example.com","emailScope":"v2-private","enabled":true,"id":"123"}}}`
	nextcloudUserWrongEmail string = `{"ocs":{"data":{"additional_mail":[],"additional_mailScope":["v2-private"],"displayname":"Nextcloud Test","displaynameScope":"v2-private","email":"other@example.com","emailScope":"v2-private","enabled":true,"id":"123"}}}`
	nextcloudUserNoEmail    string = `{"ocs":{"data":{"additional_mail":[],"additional_mailScope":["v2-private"],"displayname":"Nextcloud Test","displaynameScope":"v2-private","emailScope":"v2-private","enabled":true,"id":"123"}}}`
)

func (ts *ExternalTestSuite) TestSignupExternalNextcloud() {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/authorize?provider=nextcloud", nil)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)
	u, err := url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")
	q := u.Query()
	ts.Equal(ts.Config.External.Nextcloud.RedirectURI, q.Get("redirect_uri"))
	ts.Equal(ts.Config.External.Nextcloud.ClientID, []string{q.Get("client_id")})
	ts.Equal("code", q.Get("response_type"))

	claims := ExternalProviderClaims{}
	p := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}))
	_, err = p.ParseWithClaims(q.Get("state"), &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(ts.Config.JWT.Secret), nil
	})
	ts.Require().NoError(err)

	ts.Equal("nextcloud", claims.Provider)
	ts.Equal(ts.Config.SiteURL, claims.SiteURL)
}

func NextcloudTestSignupSetup(ts *ExternalTestSuite, tokenCount *int, userCount *int, code string, user string) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/apps/oauth2/api/v1/token":
			*tokenCount++
			ts.Equal(code, r.FormValue("code"))
			ts.Equal("authorization_code", r.FormValue("grant_type"))
			ts.Equal(ts.Config.External.Nextcloud.RedirectURI, r.FormValue("redirect_uri"))

			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"nextcloud_token","expires_in":100000}`)
		case "/ocs/v2.php/cloud/user":
			*userCount++

			// OCS-APIRequest header is needed for that endpoint, so we check it here
			ts.Equal("true", r.Header.Get("OCS-APIRequest"))
			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, user)
		default:
			w.WriteHeader(500)
			ts.Fail("unknown nextcloud oauth call %s", r.URL.Path)
		}
	}))

	ts.Config.External.Nextcloud.URL = server.URL

	return server
}

func (ts *ExternalTestSuite) TestSignupExternalNextcloudAuthorizationCode() {
	// emails from Nextcloud don't return confirm status
	ts.Config.Mailer.Autoconfirm = true

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := NextcloudTestSignupSetup(ts, &tokenCount, &userCount, code, nextcloudUser)
	defer server.Close()

	u := performAuthorization(ts, "nextcloud", code, "")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "nextcloud@example.com", "Nextcloud Test", "123", "")
}

func (ts *ExternalTestSuite) TestSignupExternalNextcloudDisableSignupErrorWhenNoUser() {
	ts.Config.DisableSignup = true

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := NextcloudTestSignupSetup(ts, &tokenCount, &userCount, code, nextcloudUser)
	defer server.Close()

	u := performAuthorization(ts, "nextcloud", code, "")

	assertAuthorizationFailure(ts, u, "Signups not allowed for this instance", "access_denied", "nextcloud@example.com")
}

func (ts *ExternalTestSuite) TestSignupExternalNextcloudDisableSignupErrorWhenEmptyEmail() {
	ts.Config.DisableSignup = true

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := NextcloudTestSignupSetup(ts, &tokenCount, &userCount, code, nextcloudUserNoEmail)
	defer server.Close()

	u := performAuthorization(ts, "nextcloud", code, "")

	assertAuthorizationFailure(ts, u, "Error getting user email from external provider", "server_error", "nextcloud@example.com")
}

func (ts *ExternalTestSuite) TestSignupExternalNextcloudDisableSignupSuccessWithPrimaryEmail() {
	ts.Config.DisableSignup = true

	ts.createUser("123", "nextcloud@example.com", "Nextcloud Test", "", "")

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := NextcloudTestSignupSetup(ts, &tokenCount, &userCount, code, nextcloudUser)
	defer server.Close()

	u := performAuthorization(ts, "nextcloud", code, "")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "nextcloud@example.com", "Nextcloud Test", "123", "")
}

func (ts *ExternalTestSuite) TestInviteTokenExternalNextcloudSuccessWhenMatchingToken() {
	// name and rest should be populated from Nextcloud API
	ts.createUser("123", "nextcloud@example.com", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := NextcloudTestSignupSetup(ts, &tokenCount, &userCount, code, nextcloudUser)
	defer server.Close()

	u := performAuthorization(ts, "nextcloud", code, "invite_token")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "nextcloud@example.com", "Nextcloud Test", "123", "")
}

func (ts *ExternalTestSuite) TestInviteTokenExternalNextcloudErrorWhenNoMatchingToken() {
	tokenCount, userCount := 0, 0
	code := "authcode"
	server := NextcloudTestSignupSetup(ts, &tokenCount, &userCount, code, nextcloudUser)
	defer server.Close()

	w := performAuthorizationRequest(ts, "nextcloud", "invite_token")
	ts.Require().Equal(http.StatusNotFound, w.Code)
}

func (ts *ExternalTestSuite) TestInviteTokenExternalNextcloudErrorWhenWrongToken() {
	ts.createUser("123", "nextcloud@example.com", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := NextcloudTestSignupSetup(ts, &tokenCount, &userCount, code, nextcloudUser)
	defer server.Close()

	w := performAuthorizationRequest(ts, "nextcloud", "wrong_token")
	ts.Require().Equal(http.StatusNotFound, w.Code)
}

func (ts *ExternalTestSuite) TestInviteTokenExternalNextcloudErrorWhenEmailDoesntMatch() {
	ts.createUser("123", "nextcloud@example.com", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	server := NextcloudTestSignupSetup(ts, &tokenCount, &userCount, code, nextcloudUserWrongEmail)
	defer server.Close()

	u := performAuthorization(ts, "nextcloud", code, "invite_token")

	assertAuthorizationFailure(ts, u, "Invited email does not match emails from external provider", "invalid_request", "")
}
