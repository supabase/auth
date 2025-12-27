package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/supabase/auth/internal/api/provider"
	"github.com/supabase/auth/internal/models"
)

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

	claims := ExternalProviderClaims{}
	p := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}))
	_, err = p.ParseWithClaims(q.Get("state"), &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(ts.Config.JWT.Secret), nil
	})
	ts.Require().NoError(err)

	ts.Equal("line", claims.Provider)
	ts.Equal(ts.Config.SiteURL, claims.SiteURL)
}

func LineTestSignupSetup(ts *ExternalTestSuite, tokenCount *int, userCount *int, code string, emails string) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2/v2.1/token":
			*tokenCount++
			ts.Equal(code, r.FormValue("code"))
			ts.Equal("authorization_code", r.FormValue("grant_type"))
			ts.Equal(ts.Config.External.Line.RedirectURI, r.FormValue("redirect_uri"))
			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"line_token","expires_in":100000}`)
		case "/oauth2/v2.1/userinfo":
			*userCount++
			var emailList []provider.Email
			if err := json.Unmarshal([]byte(emails), &emailList); err != nil {
				ts.Fail("Invalid email json %s", emails)
			}

			var email *provider.Email
			for i := range emailList {
				if emailList[i].Email != "" {
					email = &emailList[i]
					break
				}
			}

			w.Header().Add("Content-Type", "application/json")
			if email != nil {
				fmt.Fprintf(w, `
                    {
                        "sub":"123",
                        "name":"Line Test",
                        "picture":"http://example.com/avatar",
                        "email":"%v",
                        "email_verified": %v
                    }`, email.Email, email.Verified)
			} else {
				fmt.Fprint(w, `
                    {
                        "sub":"123",
                        "name":"Line Test",
                        "picture":"http://example.com/avatar"
                    }`)
			}
		default:
			w.WriteHeader(http.StatusInternalServerError)
			ts.Fail("unknown line oauth call %s", r.URL.Path)
		}
	}))

	ts.Config.External.Line.URL = server.URL
	ts.Config.External.Line.ApiURL = server.URL
	ts.Config.External.Line.EmailOptional = false

	return server
}

func (ts *ExternalTestSuite) TestSignupExternalLine_AuthorizationCode() {
	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"email":"line@example.com", "primary": true, "verified": true}]`
	server := LineTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()

	u := performAuthorization(ts, "line", code, "")
	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "line@example.com", "Line Test", "123", "http://example.com/avatar")
}

func (ts *ExternalTestSuite) TestSignupExternalLineDisableSignupErrorWhenNoUser() {
	ts.Config.DisableSignup = true

	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"email":"line@example.com", "primary": true, "verified": true}]`
	server := LineTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()

	u := performAuthorization(ts, "line", code, "")

	assertAuthorizationFailure(ts, u, "Signups not allowed for this instance", "access_denied", "line@example.com")
}

func (ts *ExternalTestSuite) TestSignupExternalLineDisableSignupErrorWhenEmptyEmail() {
	ts.Config.DisableSignup = true

	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"primary": true, "verified": true}]`
	server := LineTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()

	u := performAuthorization(ts, "line", code, "")

	assertAuthorizationFailure(ts, u, "Error getting user email from external provider", "server_error", "line@example.com")
}

func (ts *ExternalTestSuite) TestSignupExternalLineDisableSignupSuccessWithPrimaryEmail() {
	ts.Config.DisableSignup = true

	ts.createUser("123", "line@example.com", "Line Test", "http://example.com/avatar", "")

	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"email":"line@example.com", "primary": true, "verified": true}]`
	server := LineTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()

	u := performAuthorization(ts, "line", code, "")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "line@example.com", "Line Test", "123", "http://example.com/avatar")
}

func (ts *ExternalTestSuite) TestInviteTokenExternalLineSuccessWhenMatchingToken() {
	ts.createUser("123", "line@example.com", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"email":"line@example.com", "primary": true, "verified": true}]`
	server := LineTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()

	u := performAuthorization(ts, "line", code, "invite_token")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "line@example.com", "Line Test", "123", "http://example.com/avatar")
}

func (ts *ExternalTestSuite) TestInviteTokenExternalLineErrorWhenEmailDoesntMatch() {
	ts.createUser("123", "line@example.com", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"email":"other@example.com", "primary": true, "verified": true}]`
	server := LineTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()

	u := performAuthorization(ts, "line", code, "invite_token")

	assertAuthorizationFailure(ts, u, "Invited email does not match emails from external provider", "invalid_request", "")
}

func (ts *ExternalTestSuite) TestSignupExternalLineErrorWhenVerifiedFalse() {
	ts.Config.Mailer.AllowUnverifiedEmailSignIns = false

	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"email":"line@example.com", "primary": true, "verified": false}]`
	server := LineTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()

	u := performAuthorization(ts, "line", code, "")

	assertAuthorizationFailure(ts, u, "Unverified email with line. A confirmation email has been sent to your line email", "access_denied", "")
}

func (ts *ExternalTestSuite) TestSignupExternalLineErrorWhenUserBanned() {
	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"email":"line@example.com", "primary": true, "verified": true}]`
	server := LineTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()

	u := performAuthorization(ts, "line", code, "")
	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "line@example.com", "Line Test", "123", "http://example.com/avatar")

	user, err := models.FindUserByEmailAndAudience(ts.API.db, "line@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	t := time.Now().Add(24 * time.Hour)
	user.BannedUntil = &t
	require.NoError(ts.T(), ts.API.db.UpdateOnly(user, "banned_until"))

	u = performAuthorization(ts, "line", code, "")

	assertAuthorizationFailure(ts, u, "User is banned", "access_denied", "")
}
