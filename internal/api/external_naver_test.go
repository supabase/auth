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

func (ts *ExternalTestSuite) TestSignupExternalNaver() {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/authorize?provider=naver", nil)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)
	u, err := url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")
	q := u.Query()
	ts.Equal(ts.Config.External.Naver.RedirectURI, q.Get("redirect_uri"))
	ts.Equal(ts.Config.External.Naver.ClientID, []string{q.Get("client_id")})
	ts.Equal("code", q.Get("response_type"))

	claims := ExternalProviderClaims{}
	p := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}))
	_, err = p.ParseWithClaims(q.Get("state"), &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(ts.Config.JWT.Secret), nil
	})
	ts.Require().NoError(err)

	ts.Equal("naver", claims.Provider)
	ts.Equal(ts.Config.SiteURL, claims.SiteURL)
}

func NaverTestSignupSetup(ts *ExternalTestSuite, tokenCount *int, userCount *int, code string, emails string) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2.0/token":
			*tokenCount++
			ts.Equal(code, r.FormValue("code"))
			ts.Equal("authorization_code", r.FormValue("grant_type"))
			ts.Equal(ts.Config.External.Naver.RedirectURI, r.FormValue("redirect_uri"))
			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"naver_token","expires_in":100000}`)
		case "/v1/nid/me":
			*userCount++
			var emailList []provider.Email
			if err := json.Unmarshal([]byte(emails), &emailList); err != nil {
				ts.Fail("Invalid email json %s", emails)
			}

			var email *provider.Email

			for i, e := range emailList {
				if len(e.Email) > 0 {
					email = &emailList[i]
					break
				}
			}

			w.Header().Add("Content-Type", "application/json")
			if email != nil {
				fmt.Fprintf(w, `
					{
						"response": {
							"id": "123",
							"name": "Naver Test",
							"profile_image": "http://example.com/avatar",
							"email": "%v"
						}
					}`, email.Email)
			} else {
				fmt.Fprint(w, `
					{
						"response": {
							"id": "123",
							"name": "Naver Test",
							"profile_image": "http://example.com/avatar"
						}
					}`)
			}
		default:
			w.WriteHeader(500)
			ts.Fail("unknown naver oauth call %s", r.URL.Path)
		}
	}))
	ts.Config.External.Naver.URL = server.URL
	return server
}

func (ts *ExternalTestSuite) TestSignupExternalNaver_AuthorizationCode() {
	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"email":"naver@example.com", "primary": true, "verified": true}]`
	server := NaverTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()
	u := performAuthorization(ts, "naver", code, "")
	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "naver@example.com", "Naver Test", "123", "http://example.com/avatar")
}

func (ts *ExternalTestSuite) TestSignupExternalNaverDisableSignupErrorWhenNoUser() {
	ts.Config.DisableSignup = true
	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"email":"naver@example.com", "primary": true, "verified": true}]`
	server := NaverTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()

	u := performAuthorization(ts, "naver", code, "")

	assertAuthorizationFailure(ts, u, "Signups not allowed for this instance", "access_denied", "naver@example.com")
}

func (ts *ExternalTestSuite) TestSignupExternalNaverDisableSignupErrorWhenEmptyEmail() {
	ts.Config.DisableSignup = true
	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"primary": true, "verified": true}]`
	server := NaverTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()

	u := performAuthorization(ts, "naver", code, "")

	assertAuthorizationFailure(ts, u, "Error getting user email from external provider", "server_error", "naver@example.com")
}

func (ts *ExternalTestSuite) TestSignupExternalNaverDisableSignupSuccessWithPrimaryEmail() {
	ts.Config.DisableSignup = true

	ts.createUser("123", "naver@example.com", "Naver Test", "http://example.com/avatar", "")

	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"email":"naver@example.com", "primary": true, "verified": true}]`
	server := NaverTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()

	u := performAuthorization(ts, "naver", code, "")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "naver@example.com", "Naver Test", "123", "http://example.com/avatar")
}

func (ts *ExternalTestSuite) TestInviteTokenExternalNaverSuccessWhenMatchingToken() {
	// name and avatar should be populated from Naver API
	ts.createUser("123", "naver@example.com", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"email":"naver@example.com", "primary": true, "verified": true}]`
	server := NaverTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()

	u := performAuthorization(ts, "naver", code, "invite_token")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "naver@example.com", "Naver Test", "123", "http://example.com/avatar")
}

func (ts *ExternalTestSuite) TestInviteTokenExternalNaverErrorWhenNoMatchingToken() {
	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"email":"naver@example.com", "primary": true, "verified": true}]`
	server := NaverTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()

	w := performAuthorizationRequest(ts, "naver", "invite_token")
	ts.Require().Equal(http.StatusNotFound, w.Code)
}

func (ts *ExternalTestSuite) TestInviteTokenExternalNaverErrorWhenWrongToken() {
	ts.createUser("123", "naver@example.com", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"email":"naver@example.com", "primary": true, "verified": true}]`
	server := NaverTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()

	w := performAuthorizationRequest(ts, "naver", "wrong_token")
	ts.Require().Equal(http.StatusNotFound, w.Code)
}

func (ts *ExternalTestSuite) TestInviteTokenExternalNaverErrorWhenEmailDoesntMatch() {
	ts.createUser("123", "naver@example.com", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"email":"other@example.com", "primary": true, "verified": true}]`
	server := NaverTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()

	u := performAuthorization(ts, "naver", code, "invite_token")

	assertAuthorizationFailure(ts, u, "Invited email does not match emails from external provider", "invalid_request", "")
}

func (ts *ExternalTestSuite) TestSignupExternalNaverErrorWhenUserBanned() {
	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"email":"naver@example.com", "primary": true, "verified": true}]`
	server := NaverTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()

	u := performAuthorization(ts, "naver", code, "")
	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "naver@example.com", "Naver Test", "123", "http://example.com/avatar")

	user, err := models.FindUserByEmailAndAudience(ts.API.db, "naver@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	t := time.Now().Add(24 * time.Hour)
	user.BannedUntil = &t
	require.NoError(ts.T(), ts.API.db.UpdateOnly(user, "banned_until"))

	u = performAuthorization(ts, "naver", code, "")
	assertAuthorizationFailure(ts, u, "User is banned", "access_denied", "")
}
