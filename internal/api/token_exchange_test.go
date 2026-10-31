package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/supabase/auth/internal/models"
)

// FacebookAccessTokenSetup spins up a mock Graph API that answers the
// /debug_token call used by the token-exchange grant. appID controls the
// app_id returned by /debug_token, isValid controls whether the token is
// reported as valid, tokenType controls the token type (USER, PAGE, APP), and
// userID is the facebook user id returned as the token subject.
func FacebookAccessTokenSetup(ts *ExternalTestSuite, appID string, isValid bool, tokenType, userID string) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/debug_token":
			expectedAppToken := ts.Config.External.Facebook.ClientID[0] + "|" + ts.Config.External.Facebook.Secret
			ts.Equal("Bearer "+expectedAppToken, r.Header.Get("Authorization"))
			ts.NotEmpty(r.URL.Query().Get("input_token"))

			w.Header().Add("Content-Type", "application/json")
			fmt.Fprintf(w, `{"data":{"app_id":"%s","type":"%s","is_valid":%t,"user_id":"%s"}}`, appID, tokenType, isValid, userID)
		default:
			w.WriteHeader(http.StatusInternalServerError)
			ts.Fail("unknown facebook graph call %s", r.URL.Path)
		}
	}))

	ts.Config.External.Facebook.URL = server.URL

	return server
}

// createFacebookIdentity creates a confirmed user with a facebook identity
// whose provider_id is the given facebook user id, so the token-exchange grant
// can sign them in. Facebook accounts arrive verified, so the user is confirmed.
func (ts *ExternalTestSuite) createFacebookIdentity(facebookUserID, email string) *models.User {
	u := ts.createUnconfirmedFacebookIdentity(facebookUserID, email)
	now := time.Now()
	u.EmailConfirmedAt = &now
	ts.Require().NoError(ts.API.db.UpdateOnly(u, "email_confirmed_at"))
	return u
}

func (ts *ExternalTestSuite) createUnconfirmedFacebookIdentity(facebookUserID, email string) *models.User {
	u, err := models.NewUser("", email, "test", ts.Config.JWT.Aud, nil)
	ts.Require().NoError(err)
	ts.Require().NoError(ts.API.db.Create(u))

	i, err := models.NewIdentity(u, "facebook", map[string]interface{}{
		"sub":   facebookUserID,
		"email": email,
	})
	ts.Require().NoError(err)
	ts.Require().NoError(ts.API.db.Create(i))

	return u
}

func (ts *ExternalTestSuite) tokenExchange(subjectToken string) *httptest.ResponseRecorder {
	return ts.tokenExchangeWithType(subjectToken, FacebookAccessTokenType)
}

func (ts *ExternalTestSuite) tokenExchangeWithType(subjectToken, subjectTokenType string) *httptest.ResponseRecorder {
	var buffer bytes.Buffer
	ts.Require().NoError(json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"subject_token":      subjectToken,
		"subject_token_type": subjectTokenType,
	}))

	req := httptest.NewRequest(http.MethodPost, "http://localhost/token?grant_type="+TokenExchangeGrantType, &buffer)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	return w
}

func (ts *ExternalTestSuite) TestTokenExchangeSignsInExistingIdentity() {
	user := ts.createFacebookIdentity("facebookTestId", "facebook@example.com")

	server := FacebookAccessTokenSetup(ts, ts.Config.External.Facebook.ClientID[0], true, "USER", "facebookTestId")
	defer server.Close()

	w := ts.tokenExchange("valid_access_token")
	ts.Require().Equal(http.StatusOK, w.Code, w.Body.String())

	var response AccessTokenResponse
	ts.Require().NoError(json.NewDecoder(w.Body).Decode(&response))
	ts.Require().NotEmpty(response.Token)
	ts.Require().NotEmpty(response.RefreshToken)
	ts.Require().NotNil(response.User)
	ts.Equal(user.ID, response.User.ID)

	// The sign-in is recorded in the audit log, like the other grant flows.
	logs, err := models.FindAuditLogEntries(ts.API.db, []string{"action"}, string(models.LoginAction), nil)
	ts.Require().NoError(err)
	ts.Require().NotEmpty(logs)
	ts.Equal(string(models.LoginAction), logs[0].Payload["action"])
}

func (ts *ExternalTestSuite) TestTokenExchangeNoIdentityIsRejected() {
	// No identity is created, so there is nobody to sign in.
	server := FacebookAccessTokenSetup(ts, ts.Config.External.Facebook.ClientID[0], true, "USER", "facebookTestId")
	defer server.Close()

	w := ts.tokenExchange("valid_access_token")
	ts.Require().Equal(http.StatusBadRequest, w.Code)
}

func (ts *ExternalTestSuite) TestTokenExchangeRejectsBannedUser() {
	user := ts.createFacebookIdentity("facebookTestId", "facebook@example.com")
	t := time.Now().Add(24 * time.Hour)
	user.BannedUntil = &t
	ts.Require().NoError(ts.API.db.UpdateOnly(user, "banned_until"))

	server := FacebookAccessTokenSetup(ts, ts.Config.External.Facebook.ClientID[0], true, "USER", "facebookTestId")
	defer server.Close()

	w := ts.tokenExchange("valid_access_token")
	ts.Require().Equal(http.StatusBadRequest, w.Code)
}

func (ts *ExternalTestSuite) TestTokenExchangeRejectsUnconfirmedUser() {
	ts.createUnconfirmedFacebookIdentity("facebookTestId", "facebook@example.com")

	server := FacebookAccessTokenSetup(ts, ts.Config.External.Facebook.ClientID[0], true, "USER", "facebookTestId")
	defer server.Close()

	w := ts.tokenExchange("valid_access_token")
	ts.Require().Equal(http.StatusBadRequest, w.Code)
}

func (ts *ExternalTestSuite) TestTokenExchangeAllowsUnconfirmedWhenConfigured() {
	ts.Config.Mailer.AllowUnverifiedEmailSignIns = true
	defer func() { ts.Config.Mailer.AllowUnverifiedEmailSignIns = false }()
	user := ts.createUnconfirmedFacebookIdentity("facebookTestId", "facebook@example.com")

	server := FacebookAccessTokenSetup(ts, ts.Config.External.Facebook.ClientID[0], true, "USER", "facebookTestId")
	defer server.Close()

	w := ts.tokenExchange("valid_access_token")
	ts.Require().Equal(http.StatusOK, w.Code, w.Body.String())

	var response AccessTokenResponse
	ts.Require().NoError(json.NewDecoder(w.Body).Decode(&response))
	ts.Equal(user.ID, response.User.ID)
}

func (ts *ExternalTestSuite) TestTokenExchangeRejectsTokenFromAnotherApp() {
	ts.createFacebookIdentity("facebookTestId", "facebook@example.com")

	server := FacebookAccessTokenSetup(ts, "some_other_app_id", true, "USER", "facebookTestId")
	defer server.Close()

	w := ts.tokenExchange("token_for_another_app")
	ts.Require().Equal(http.StatusBadRequest, w.Code)
}

func (ts *ExternalTestSuite) TestTokenExchangeAcceptsSecondaryClientID() {
	primary := ts.Config.External.Facebook.ClientID[0]
	ts.Config.External.Facebook.ClientID = []string{primary, "second_app_id"}
	defer func() { ts.Config.External.Facebook.ClientID = []string{primary} }()

	user := ts.createFacebookIdentity("facebookTestId", "facebook@example.com")

	server := FacebookAccessTokenSetup(ts, "second_app_id", true, "USER", "facebookTestId")
	defer server.Close()

	w := ts.tokenExchange("token_for_second_app")
	ts.Require().Equal(http.StatusOK, w.Code, w.Body.String())

	var response AccessTokenResponse
	ts.Require().NoError(json.NewDecoder(w.Body).Decode(&response))
	ts.Equal(user.ID, response.User.ID)
}

func (ts *ExternalTestSuite) TestTokenExchangeRejectsInvalidToken() {
	ts.createFacebookIdentity("facebookTestId", "facebook@example.com")

	server := FacebookAccessTokenSetup(ts, ts.Config.External.Facebook.ClientID[0], false, "USER", "facebookTestId")
	defer server.Close()

	w := ts.tokenExchange("invalid_token")
	ts.Require().Equal(http.StatusBadRequest, w.Code)
}

func (ts *ExternalTestSuite) TestTokenExchangeRejectsNonUserToken() {
	ts.createFacebookIdentity("facebookTestId", "facebook@example.com")

	server := FacebookAccessTokenSetup(ts, ts.Config.External.Facebook.ClientID[0], true, "PAGE", "facebookTestId")
	defer server.Close()

	w := ts.tokenExchange("page_token")
	ts.Require().Equal(http.StatusBadRequest, w.Code)
}

func (ts *ExternalTestSuite) TestTokenExchangeMissingSubjectToken() {
	w := ts.tokenExchange("")
	ts.Require().Equal(http.StatusBadRequest, w.Code)
}

func (ts *ExternalTestSuite) TestTokenExchangeMissingSubjectTokenType() {
	w := ts.tokenExchangeWithType("some_token", "")
	ts.Require().Equal(http.StatusBadRequest, w.Code)
}

func (ts *ExternalTestSuite) TestTokenExchangeUnsupportedSubjectTokenType() {
	w := ts.tokenExchangeWithType("some_token", "urn:ietf:params:oauth:token-type:id_token")
	ts.Require().Equal(http.StatusBadRequest, w.Code)
}

func (ts *ExternalTestSuite) TestTokenExchangeProviderDisabled() {
	ts.Config.External.Facebook.Enabled = false
	defer func() { ts.Config.External.Facebook.Enabled = true }()

	w := ts.tokenExchange("some_token")
	ts.Require().Equal(http.StatusBadRequest, w.Code)
}
