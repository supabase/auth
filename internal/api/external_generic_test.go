package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"time"

	jwt "github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api/provider"
	"github.com/supabase/auth/internal/models"
)

func (ts *ExternalTestSuite) TestSignupExternalGeneric() {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/authorize?provider=generic1", nil)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)
	u, err := url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")
	q := u.Query()
	ts.Equal(ts.Config.External.Generic1.RedirectURI, q.Get("redirect_uri"))
	ts.Equal(ts.Config.External.Generic1.ClientID, []string{q.Get("client_id")})
	ts.Equal("code", q.Get("response_type"))

	claims := ExternalProviderClaims{}
	p := jwt.Parser{ValidMethods: []string{jwt.SigningMethodHS256.Name}}
	_, err = p.ParseWithClaims(q.Get("state"), &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(ts.Config.JWT.Secret), nil
	})
	ts.Require().NoError(err)

	ts.Equal("generic1", claims.Provider)
	ts.Equal(ts.Config.SiteURL, claims.SiteURL)
}

func GenericTestSignupSetup(ts *ExternalTestSuite, tokenCount *int, userCount *int, code string, emails string) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			*tokenCount++
			ts.Equal(code, r.FormValue("code"))
			ts.Equal("authorization_code", r.FormValue("grant_type"))
			ts.Equal(ts.Config.External.Generic1.RedirectURI, r.FormValue("redirect_uri"))
			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"generic_token","expires_in":100000}`)
		case "/profile":
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

			if email == nil {
				w.WriteHeader(400)
				return
			}

			w.Header().Add("Content-Type", "application/json")
			fmt.Fprintf(w, `
				{
					"id":123, 
					"generic_account": {
						"profile": {
							"nickname":"Generic Test",
							"profile_image_url":"http://example.com/avatar"
						},
						"email": "%v",
						"is_email_valid": %v,
						"is_email_verified": %v
					}
				}`, email.Email, email.Verified, email.Verified)
		default:
			w.WriteHeader(500)
			ts.Fail("unknown generic oauth call %s", r.URL.Path)
		}
	}))
	ts.Config.External.Generic1.URL = server.URL
	return server
}

func (ts *ExternalTestSuite) TestSignupExternalGeneric_AuthorizationCode() {
	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"email":"generic@example.com", "primary": true, "verified": true}]`
	server := GenericTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()
	u := performAuthorization(ts, "generic1", code, "")
	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "generic@example.com", "Generic Test", "123", "http://example.com/avatar")
}

func (ts *ExternalTestSuite) TestSignupExternalGenericDisableSignupErrorWhenNoUser() {
	ts.Config.DisableSignup = true
	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"email":"generic@example.com", "primary": true, "verified": true}]`
	server := GenericTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()

	u := performAuthorization(ts, "generic1", code, "")

	assertAuthorizationFailure(ts, u, "Signups not allowed for this instance", "access_denied", "generic@example.com")
}

func (ts *ExternalTestSuite) TestSignupExternalGenericDisableSignupErrorWhenEmptyEmail() {
	ts.Config.DisableSignup = true
	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"primary": true, "verified": true}]`
	server := GenericTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()

	u := performAuthorization(ts, "generic1", code, "")

	assertAuthorizationFailure(ts, u, "Error getting user email from external provider", "server_error", "generic@example.com")
}

func (ts *ExternalTestSuite) TestSignupExternalGenericDisableSignupSuccessWithPrimaryEmail() {
	ts.Config.DisableSignup = true

	ts.createUser("123", "generic@example.com", "Generic Test", "http://example.com/avatar", "")

	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"email":"generic@example.com", "primary": true, "verified": true}]`
	server := GenericTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()

	u := performAuthorization(ts, "generic1", code, "")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "generic@example.com", "Generic Test", "123", "http://example.com/avatar")
}

func (ts *ExternalTestSuite) TestInviteTokenExternalGenericSuccessWhenMatchingToken() {
	// name and avatar should be populated from external API
	ts.createUser("123", "generic@example.com", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"email":"generic@example.com", "primary": true, "verified": true}]`
	server := GenericTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()

	u := performAuthorization(ts, "generic1", code, "invite_token")

	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "generic@example.com", "Generic Test", "123", "http://example.com/avatar")
}

func (ts *ExternalTestSuite) TestInviteTokenExternalGenericErrorWhenNoMatchingToken() {
	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"email":"generic@example.com", "primary": true, "verified": true}]`
	server := GenericTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()

	w := performAuthorizationRequest(ts, "generic1", "invite_token")
	ts.Require().Equal(http.StatusNotFound, w.Code)
}

func (ts *ExternalTestSuite) TestInviteTokenExternalGenericErrorWhenWrongToken() {
	ts.createUser("123", "generic@example.com", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"email":"generic@example.com", "primary": true, "verified": true}]`
	server := GenericTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()

	w := performAuthorizationRequest(ts, "generic1", "wrong_token")
	ts.Require().Equal(http.StatusNotFound, w.Code)
}

func (ts *ExternalTestSuite) TestInviteTokenExternalGenericErrorWhenEmailDoesntMatch() {
	ts.createUser("123", "generic@example.com", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"email":"other@example.com", "primary": true, "verified": true}]`
	server := GenericTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()

	u := performAuthorization(ts, "generic1", code, "invite_token")

	assertAuthorizationFailure(ts, u, "Invited email does not match emails from external provider", "invalid_request", "")
}

func (ts *ExternalTestSuite) TestSignupExternalGenericErrorWhenVerifiedFalse() {
	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"email":"generic@example.com", "primary": true, "verified": false}]`
	server := GenericTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()

	u := performAuthorization(ts, "generic1", code, "")

	v, err := url.ParseQuery(u.Fragment)
	ts.Require().NoError(err)
	ts.Equal("unauthorized_client", v.Get("error"))
	ts.Equal("401", v.Get("error_code"))
	ts.Equal("Unverified email with generic", v.Get("error_description"))
	assertAuthorizationFailure(ts, u, "", "", "")
}

func (ts *ExternalTestSuite) TestSignupExternalGenericErrorWhenUserBanned() {
	tokenCount, userCount := 0, 0
	code := "authcode"
	emails := `[{"email":"generic@example.com", "primary": true, "verified": true}]`
	server := GenericTestSignupSetup(ts, &tokenCount, &userCount, code, emails)
	defer server.Close()

	u := performAuthorization(ts, "generic1", code, "")
	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "generic@example.com", "Generic Test", "123", "http://example.com/avatar")

	user, err := models.FindUserByEmailAndAudience(ts.API.db, "generic@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	t := time.Now().Add(24 * time.Hour)
	user.BannedUntil = &t
	require.NoError(ts.T(), ts.API.db.UpdateOnly(user, "banned_until"))

	u = performAuthorization(ts, "generic1", code, "")
	assertAuthorizationFailure(ts, u, "User is unauthorized", "unauthorized_client", "")
}
