package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/supabase/auth/internal/api/provider"
	"github.com/supabase/auth/internal/models"
)

const (
	lineUser        string = `{"name":"LINE Test","email":"line@example.com","sub":"linetestid","picture":"http://example.com/avatar"}`
	lineUserNoEmail string = `{"name":"LINE Test","sub":"linetestid","picture":"http://example.com/avatar"}`
)

// mintLineIDToken builds an ID token the way LINE does: an HS256 JWT signed with
// the channel secret (GOTRUE_EXTERNAL_LINE_SECRET in hack/test.env).
func mintLineIDToken(ts *ExternalTestSuite, user string) string {
	var fields struct {
		Sub     string `json:"sub,omitempty"`
		Name    string `json:"name,omitempty"`
		Picture string `json:"picture,omitempty"`
		Email   string `json:"email,omitempty"`
	}
	if err := json.Unmarshal([]byte(user), &fields); err != nil {
		panic(err)
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"iss": provider.IssuerLINE,
		"sub": fields.Sub,
		"aud": ts.Config.External.Line.ClientID[0],
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
	}
	if fields.Name != "" {
		claims["name"] = fields.Name
	}
	if fields.Picture != "" {
		claims["picture"] = fields.Picture
	}
	if fields.Email != "" {
		claims["email"] = fields.Email
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(ts.Config.External.Line.Secret))
	if err != nil {
		panic(err)
	}
	return signed
}

func (ts *ExternalTestSuite) TestSignupExternalLine() {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/authorize?provider=line", nil)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)
	u, err := url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")
	q := u.Query()
	ts.Equal(ts.Config.External.Line.RedirectURI, q.Get("redirect_uri"))
	ts.Equal(ts.Config.External.Line.ClientID, []string{q.Get("client_id")})
	ts.Equal("code", q.Get("response_type"))
	ts.Equal("openid profile email", q.Get("scope"))

	assertValidOAuthState(ts, q.Get("state"), "line")
}

func LineTestSignupSetup(ts *ExternalTestSuite, tokenCount *int, code string, user string) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2/v2.1/token":
			*tokenCount++
			ts.Equal(code, r.FormValue("code"))
			ts.Equal("authorization_code", r.FormValue("grant_type"))
			ts.Equal(ts.Config.External.Line.RedirectURI, r.FormValue("redirect_uri"))

			w.Header().Add("Content-Type", "application/json")
			fmt.Fprintf(w, `{"access_token":"line_token","expires_in":100000,"id_token":%q}`, mintLineIDToken(ts, user))
		default:
			w.WriteHeader(500)
			ts.Fail("unknown line oauth call %s", r.URL.Path)
		}
	}))

	ts.Config.External.Line.URL = server.URL

	return server
}

func (ts *ExternalTestSuite) TestSignupExternalLine_AuthorizationCode() {
	ts.Config.DisableSignup = false
	tokenCount := 0
	code := "authcode"
	server := LineTestSignupSetup(ts, &tokenCount, code, lineUser)
	defer server.Close()

	u := performAuthorization(ts, "line", code, "")

	assertAuthorizationSuccess(ts, u, tokenCount, -1, "line@example.com", "LINE Test", "linetestid", "http://example.com/avatar")
}

func (ts *ExternalTestSuite) TestSignupExternalLineDisableSignupErrorWhenNoUser() {
	ts.Config.DisableSignup = true
	tokenCount := 0
	code := "authcode"
	server := LineTestSignupSetup(ts, &tokenCount, code, lineUser)
	defer server.Close()

	u := performAuthorization(ts, "line", code, "")

	assertAuthorizationFailure(ts, u, "Signups not allowed for this instance", "access_denied", "line@example.com")
}

func (ts *ExternalTestSuite) TestSignupExternalLineDisableSignupErrorWhenNoEmail() {
	ts.Config.DisableSignup = true
	tokenCount := 0
	code := "authcode"
	server := LineTestSignupSetup(ts, &tokenCount, code, lineUserNoEmail)
	defer server.Close()

	u := performAuthorization(ts, "line", code, "")

	assertAuthorizationFailure(ts, u, "Error getting user email from external provider", "server_error", "line@example.com")
}

func (ts *ExternalTestSuite) TestSignupExternalLineDisableSignupSuccessWithPrimaryEmail() {
	ts.Config.DisableSignup = true

	ts.createUser("linetestid", "line@example.com", "LINE Test", "http://example.com/avatar", "")

	tokenCount := 0
	code := "authcode"
	server := LineTestSignupSetup(ts, &tokenCount, code, lineUser)
	defer server.Close()

	u := performAuthorization(ts, "line", code, "")

	assertAuthorizationSuccess(ts, u, tokenCount, -1, "line@example.com", "LINE Test", "linetestid", "http://example.com/avatar")
}

func (ts *ExternalTestSuite) TestInviteTokenExternalLineSuccessWhenMatchingToken() {
	// name and avatar should be populated from LINE's ID token
	ts.createUser("linetestid", "line@example.com", "", "", "invite_token")

	tokenCount := 0
	code := "authcode"
	server := LineTestSignupSetup(ts, &tokenCount, code, lineUser)
	defer server.Close()

	u := performAuthorization(ts, "line", code, "invite_token")

	assertAuthorizationSuccess(ts, u, tokenCount, -1, "line@example.com", "LINE Test", "linetestid", "http://example.com/avatar")
}

func (ts *ExternalTestSuite) TestInviteTokenExternalLineErrorWhenNoMatchingToken() {
	tokenCount := 0
	code := "authcode"
	server := LineTestSignupSetup(ts, &tokenCount, code, lineUser)
	defer server.Close()

	w := performAuthorizationRequest(ts, "line", "invite_token")
	ts.Require().Equal(http.StatusNotFound, w.Code)
}

func (ts *ExternalTestSuite) TestInviteTokenExternalLineErrorWhenWrongToken() {
	ts.createUser("linetestid", "line@example.com", "", "", "invite_token")

	tokenCount := 0
	code := "authcode"
	server := LineTestSignupSetup(ts, &tokenCount, code, lineUser)
	defer server.Close()

	w := performAuthorizationRequest(ts, "line", "wrong_token")
	ts.Require().Equal(http.StatusNotFound, w.Code)
}

func (ts *ExternalTestSuite) TestInviteTokenExternalLineErrorWhenEmailDoesntMatch() {
	ts.createUser("linetestid", "line@example.com", "", "", "invite_token")

	tokenCount := 0
	code := "authcode"
	lineUserWrongEmail := `{"name":"LINE Test","email":"other@example.com","sub":"linetestid","picture":"http://example.com/avatar"}`
	server := LineTestSignupSetup(ts, &tokenCount, code, lineUserWrongEmail)
	defer server.Close()

	u := performAuthorization(ts, "line", code, "invite_token")

	assertAuthorizationFailure(ts, u, "Invited email does not match emails from external provider", "invalid_request", "")
}

func (ts *ExternalTestSuite) TestSignupExternalLineErrorWhenUserBanned() {
	tokenCount := 0
	code := "authcode"
	server := LineTestSignupSetup(ts, &tokenCount, code, lineUser)
	defer server.Close()

	u := performAuthorization(ts, "line", code, "")
	assertAuthorizationSuccess(ts, u, tokenCount, -1, "line@example.com", "LINE Test", "linetestid", "http://example.com/avatar")

	user, err := models.FindUserByEmailAndAudience(ts.API.db, "line@example.com", ts.Config.JWT.Aud)
	ts.Require().NoError(err)
	t := time.Now().Add(24 * time.Hour)
	user.BannedUntil = &t
	ts.Require().NoError(ts.API.db.UpdateOnly(user, "banned_until"))

	u = performAuthorization(ts, "line", code, "")
	assertAuthorizationFailure(ts, u, "User is banned", "access_denied", "")
}
