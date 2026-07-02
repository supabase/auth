package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
)

// FacebookAccessTokenSetup spins up a mock Graph API that answers the
// /debug_token and /me calls used by the access_token grant. appID controls the
// app_id returned by /debug_token, isValid controls whether the token is
// reported as valid.
func FacebookAccessTokenSetup(ts *ExternalTestSuite, appID string, isValid bool, user string) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/debug_token":
			expectedAppToken := ts.Config.External.Facebook.ClientID[0] + "|" + ts.Config.External.Facebook.Secret
			ts.Equal(expectedAppToken, r.URL.Query().Get("access_token"))

			w.Header().Add("Content-Type", "application/json")
			fmt.Fprintf(w, `{"data":{"app_id":"%s","is_valid":%t,"user_id":"facebookTestId"}}`, appID, isValid)
		case "/me":
			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, user)
		default:
			w.WriteHeader(http.StatusInternalServerError)
			ts.Fail("unknown facebook graph call %s", r.URL.Path)
		}
	}))

	ts.Config.External.Facebook.URL = server.URL

	return server
}

func (ts *ExternalTestSuite) accessTokenGrant(provider, accessToken string) *httptest.ResponseRecorder {
	var buffer bytes.Buffer
	ts.Require().NoError(json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"provider":     provider,
		"access_token": accessToken,
	}))

	req := httptest.NewRequest(http.MethodPost, "http://localhost/token?grant_type=access_token", &buffer)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	return w
}

func (ts *ExternalTestSuite) TestAccessTokenGrantFacebookSuccess() {
	server := FacebookAccessTokenSetup(ts, ts.Config.External.Facebook.ClientID[0], true, facebookUser)
	defer server.Close()

	w := ts.accessTokenGrant("facebook", "valid_access_token")
	ts.Require().Equal(http.StatusOK, w.Code, w.Body.String())

	var response AccessTokenResponse
	ts.Require().NoError(json.NewDecoder(w.Body).Decode(&response))
	ts.Require().NotEmpty(response.Token)
	ts.Equal("facebook@example.com", response.User.GetEmail())
}

func (ts *ExternalTestSuite) TestAccessTokenGrantFacebookRejectsTokenFromAnotherApp() {
	server := FacebookAccessTokenSetup(ts, "some_other_app_id", true, facebookUser)
	defer server.Close()

	w := ts.accessTokenGrant("facebook", "token_for_another_app")
	ts.Require().Equal(http.StatusBadRequest, w.Code)
}

func (ts *ExternalTestSuite) TestAccessTokenGrantFacebookRejectsInvalidToken() {
	server := FacebookAccessTokenSetup(ts, ts.Config.External.Facebook.ClientID[0], false, facebookUser)
	defer server.Close()

	w := ts.accessTokenGrant("facebook", "invalid_token")
	ts.Require().Equal(http.StatusBadRequest, w.Code)
}

func (ts *ExternalTestSuite) TestAccessTokenGrantMissingAccessToken() {
	w := ts.accessTokenGrant("facebook", "")
	ts.Require().Equal(http.StatusBadRequest, w.Code)
}

func (ts *ExternalTestSuite) TestAccessTokenGrantUnsupportedProvider() {
	// google does not implement AccessTokenVerifier
	ts.Config.External.Google.Enabled = true
	ts.Config.External.Google.ClientID = []string{"googleclientid"}
	ts.Config.External.Google.Secret = "googlesecret"

	w := ts.accessTokenGrant("google", "some_google_token")
	ts.Require().Equal(http.StatusBadRequest, w.Code)
}
