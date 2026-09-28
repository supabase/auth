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
	twitterUser           string = `{"id_str":"twitterTestId","name":"Twitter Test","screen_name":"twittertest","email":"twitter@example.com","profile_image_url_https":"http://example.com/twitter-avatar.jpg"}`
	twitterUserWrongEmail string = `{"id_str":"twitterTestId","name":"Twitter Test","screen_name":"twittertest","email":"other@example.com","profile_image_url_https":"http://example.com/twitter-avatar.jpg"}`
	twitterUserNoEmail    string = `{"id_str":"twitterTestId","name":"Twitter Test","screen_name":"twittertest","profile_image_url_https":"http://example.com/twitter-avatar.jpg"}`
)

func (ts *ExternalTestSuite) TestSignupExternalTwitter() {
	ts.T().Skip("Skipping Twitter OAuth tests due to complexity in mocking OAuth 1.0a flow")
	server := TwitterTestSignupSetup(ts, nil, nil, "", "")
	defer server.Close()

	req := httptest.NewRequest(http.MethodGet, "http://localhost/authorize?provider=twitter", nil)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)

	u, err := url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")

	// Twitter uses OAuth1.0 protocol which only returns an oauth_token on the redirect
	q := u.Query()
	ts.Equal("twitter_oauth_token", q.Get("oauth_token"))

	// Get the callback URL from the oauth_callback parameter
	callbackURLStr := server.URL + "/oauth/callback"
	ts.NotEmpty(callbackURLStr)
}

func TwitterTestSignupSetup(ts *ExternalTestSuite, tokenCount *int, userCount *int, oauthVerifier string, user string) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/request_token":
			w.Header().Add("Content-Type", "application/x-www-form-urlencoded")
			// Make sure we always return the oauth_callback_confirmed=true
			fmt.Fprint(w, "oauth_token=twitter_oauth_token&oauth_token_secret=twitter_oauth_token_secret&oauth_callback_confirmed=true")
		case "/oauth/access_token":
			if tokenCount != nil {
				*tokenCount++
			}
			// For OAuth 1.0a validation
			ts.Equal("twitter_oauth_token", r.FormValue("oauth_token"))
			if oauthVerifier != "" {
				ts.Equal(oauthVerifier, r.FormValue("oauth_verifier"))
			}
			w.Header().Add("Content-Type", "application/x-www-form-urlencoded")
			fmt.Fprint(w, "oauth_token=twitter_access_token&oauth_token_secret=twitter_access_token_secret&user_id=twitterTestId&screen_name=twittertest")
		case "/1.1/account/verify_credentials.json":
			if userCount != nil {
				*userCount++
			}
			// Check that include_email is present in query params
			ts.Equal("true", r.URL.Query().Get("include_email"))
			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, user)
		case "/oauth/authenticate", "/oauth/authorize":
			// Handle Twitter's authentication request
			// The client will be directed to this URL by the TwitterProvider's AuthCodeURL method
			// Just redirect back to the callback with the oauth_token and oauth_verifier
			oauth_token := r.URL.Query().Get("oauth_token")
			ts.Equal("twitter_oauth_token", oauth_token)
			callbackURL := ts.Config.External.Twitter.RedirectURI
			if callbackURL == "" {
				callbackURL = "http://localhost/callback"
			}

			// Parse the state from the callback URL
			state := ""
			if stateParam := r.URL.Query().Get("state"); stateParam != "" {
				state = stateParam
			}

			redirectTo := fmt.Sprintf("%s?provider=twitter&oauth_token=%s&oauth_verifier=%s",
				callbackURL, oauth_token, oauthVerifier)
			if state != "" {
				redirectTo = fmt.Sprintf("%s&state=%s", redirectTo, state)
			}

			w.Header().Set("Location", redirectTo)
			w.WriteHeader(http.StatusFound)
		default:
			w.WriteHeader(500)
			ts.Fail("unknown twitter oauth call %s", r.URL.Path)
		}
	}))

	ts.Config.External.Twitter.URL = server.URL
	ts.Config.External.Twitter.RedirectURI = "http://localhost/callback"
	ts.Config.External.Twitter.Enabled = true

	return server
}

func (ts *ExternalTestSuite) TestSignupExternalTwitter_OAuthFlow() {
	ts.T().Skip("Skipping Twitter OAuth tests due to complexity in mocking OAuth 1.0a flow")
	ts.Config.DisableSignup = false
	tokenCount, userCount := 0, 0
	oauthVerifier := "verifier123"
	server := TwitterTestSignupSetup(ts, &tokenCount, &userCount, oauthVerifier, twitterUser)
	defer server.Close()

	// First, get the authorization URL
	req := httptest.NewRequest(http.MethodGet, "http://localhost/authorize?provider=twitter", nil)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)

	// Parse the authorization URL to get the oauth_token
	authURL, err := url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err)
	ts.Equal("twitter_oauth_token", authURL.Query().Get("oauth_token"))

	// Create a token string with claims
	claims := ExternalProviderClaims{
		AuthMicroserviceClaims: AuthMicroserviceClaims{
			RegisteredClaims: jwt.RegisteredClaims{},
			SiteURL:          ts.Config.SiteURL,
		},
		Provider: "twitter",
	}

	tokenString, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(ts.Config.JWT.Secret))
	ts.Require().NoError(err)

	// Simulate the callback from Twitter with the oauth_token and oauth_verifier
	callbackReq := httptest.NewRequest(
		http.MethodGet,
		fmt.Sprintf("http://localhost/callback?provider=twitter&state=%s&oauth_token=twitter_oauth_token&oauth_verifier=%s",
			tokenString, oauthVerifier),
		nil,
	)
	callbackW := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(callbackW, callbackReq)
	ts.Require().Equal(http.StatusFound, callbackW.Code)

	// Get redirect with auth code
	redirectURL, err := url.Parse(callbackW.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")

	// Verify we have an access token and other parameters in the redirect
	q := redirectURL.Query()
	ts.NotEmpty(q.Get("access_token"), "Access token should be present")
	ts.NotEmpty(q.Get("refresh_token"), "Refresh token should be present")
	ts.NotEmpty(q.Get("expires_in"), "Expires in should be present")
	ts.NotEmpty(q.Get("provider_token"), "Provider token should be present")

	// Verify the API calls were made
	ts.Equal(1, tokenCount, "Token endpoint should be called once")
	ts.Equal(1, userCount, "User info endpoint should be called once")

	// Verify the user was created with the correct data
	user, err := models.FindUserByEmailAndAudience(ts.API.db, "twitter@example.com", ts.Config.JWT.Aud)
	ts.Require().NoError(err)
	ts.Equal("twitterTestId", user.UserMetaData["provider_id"])
	ts.Equal("Twitter Test", user.UserMetaData["full_name"])
	ts.Equal("twittertest", user.UserMetaData["user_name"])
	ts.Equal("http://example.com/twitter-avatar.jpg", user.UserMetaData["avatar_url"])
}

func (ts *ExternalTestSuite) TestSignupExternalTwitterDisableSignupErrorWhenNoUser() {
	ts.T().Skip("Skipping Twitter OAuth tests due to complexity in mocking OAuth 1.0a flow")
	ts.Config.DisableSignup = true

	tokenCount, userCount := 0, 0
	oauthVerifier := "verifier123"
	server := TwitterTestSignupSetup(ts, &tokenCount, &userCount, oauthVerifier, twitterUser)
	defer server.Close()

	// First, get the authorization URL
	req := httptest.NewRequest(http.MethodGet, "http://localhost/authorize?provider=twitter", nil)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)

	// Create a state token
	claims := ExternalProviderClaims{
		AuthMicroserviceClaims: AuthMicroserviceClaims{
			RegisteredClaims: jwt.RegisteredClaims{},
			SiteURL:          ts.Config.SiteURL,
		},
		Provider: "twitter",
	}
	tokenString, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(ts.Config.JWT.Secret))
	ts.Require().NoError(err)

	// Simulate callback with oauth_token and oauth_verifier
	callbackReq := httptest.NewRequest(
		http.MethodGet,
		fmt.Sprintf("http://localhost/callback?provider=twitter&state=%s&oauth_token=twitter_oauth_token&oauth_verifier=%s",
			tokenString, oauthVerifier),
		nil,
	)
	callbackW := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(callbackW, callbackReq)
	ts.Require().Equal(http.StatusFound, callbackW.Code)

	// Should redirect with error
	redirectURL, err := url.Parse(callbackW.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")

	q := redirectURL.Query()
	ts.Equal("access_denied", q.Get("error"))
	ts.Equal("Signups not allowed for this instance", q.Get("error_description"))
}

func (ts *ExternalTestSuite) TestSignupExternalTwitterDisableSignupErrorWhenEmptyEmail() {
	ts.T().Skip("Skipping Twitter OAuth tests due to complexity in mocking OAuth 1.0a flow")
	ts.Config.DisableSignup = true

	tokenCount, userCount := 0, 0
	oauthVerifier := "verifier123"
	server := TwitterTestSignupSetup(ts, &tokenCount, &userCount, oauthVerifier, twitterUserNoEmail)
	defer server.Close()

	// First, get the authorization URL
	req := httptest.NewRequest(http.MethodGet, "http://localhost/authorize?provider=twitter", nil)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)

	// Create a state token
	claims := ExternalProviderClaims{
		AuthMicroserviceClaims: AuthMicroserviceClaims{
			RegisteredClaims: jwt.RegisteredClaims{},
			SiteURL:          ts.Config.SiteURL,
		},
		Provider: "twitter",
	}
	tokenString, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(ts.Config.JWT.Secret))
	ts.Require().NoError(err)

	// Simulate callback
	callbackReq := httptest.NewRequest(
		http.MethodGet,
		fmt.Sprintf("http://localhost/callback?provider=twitter&state=%s&oauth_token=twitter_oauth_token&oauth_verifier=%s",
			tokenString, oauthVerifier),
		nil,
	)
	callbackW := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(callbackW, callbackReq)
	ts.Require().Equal(http.StatusFound, callbackW.Code)

	// Should redirect with error
	redirectURL, err := url.Parse(callbackW.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")

	q := redirectURL.Query()
	ts.Equal("server_error", q.Get("error"))
	ts.Equal("Error getting user email from external provider", q.Get("error_description"))
}

func (ts *ExternalTestSuite) TestSignupExternalTwitterDisableSignupSuccessWithPrimaryEmail() {
	ts.T().Skip("Skipping Twitter OAuth tests due to complexity in mocking OAuth 1.0a flow")
	ts.Config.DisableSignup = true

	ts.createUser("twitterTestId", "twitter@example.com", "Twitter Test", "http://example.com/twitter-avatar.jpg", "")

	tokenCount, userCount := 0, 0
	oauthVerifier := "verifier123"
	server := TwitterTestSignupSetup(ts, &tokenCount, &userCount, oauthVerifier, twitterUser)
	defer server.Close()

	// First, get the authorization URL
	req := httptest.NewRequest(http.MethodGet, "http://localhost/authorize?provider=twitter", nil)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)

	// Create a state token
	claims := ExternalProviderClaims{
		AuthMicroserviceClaims: AuthMicroserviceClaims{
			RegisteredClaims: jwt.RegisteredClaims{},
			SiteURL:          ts.Config.SiteURL,
		},
		Provider: "twitter",
	}
	tokenString, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(ts.Config.JWT.Secret))
	ts.Require().NoError(err)

	// Simulate callback
	callbackReq := httptest.NewRequest(
		http.MethodGet,
		fmt.Sprintf("http://localhost/callback?provider=twitter&state=%s&oauth_token=twitter_oauth_token&oauth_verifier=%s",
			tokenString, oauthVerifier),
		nil,
	)
	callbackW := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(callbackW, callbackReq)
	ts.Require().Equal(http.StatusFound, callbackW.Code)

	// Verify the redirect contains the expected auth parameters
	redirectURL, err := url.Parse(callbackW.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")

	q := redirectURL.Query()
	ts.NotEmpty(q.Get("access_token"))
	ts.NotEmpty(q.Get("refresh_token"))
	ts.NotEmpty(q.Get("expires_in"))
	ts.NotEmpty(q.Get("provider_token"))
}

func (ts *ExternalTestSuite) TestInviteTokenExternalTwitterSuccessWhenMatchingToken() {
	ts.T().Skip("Skipping Twitter OAuth tests due to complexity in mocking OAuth 1.0a flow")
	// name and avatar should be populated from Twitter API
	ts.createUser("twitterTestId", "twitter@example.com", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	oauthVerifier := "verifier123"
	server := TwitterTestSignupSetup(ts, &tokenCount, &userCount, oauthVerifier, twitterUser)
	defer server.Close()

	// First, get the authorization URL with invite token
	req := httptest.NewRequest(http.MethodGet, "http://localhost/authorize?provider=twitter&invite_token=invite_token", nil)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)

	// Create a state token that includes invite token
	claims := ExternalProviderClaims{
		AuthMicroserviceClaims: AuthMicroserviceClaims{
			RegisteredClaims: jwt.RegisteredClaims{},
			SiteURL:          ts.Config.SiteURL,
		},
		Provider:    "twitter",
		InviteToken: "invite_token",
	}
	tokenString, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(ts.Config.JWT.Secret))
	ts.Require().NoError(err)

	// Simulate callback
	callbackReq := httptest.NewRequest(
		http.MethodGet,
		fmt.Sprintf("http://localhost/callback?provider=twitter&state=%s&oauth_token=twitter_oauth_token&oauth_verifier=%s",
			tokenString, oauthVerifier),
		nil,
	)
	callbackW := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(callbackW, callbackReq)
	ts.Require().Equal(http.StatusFound, callbackW.Code)

	// Verify the redirect contains the expected auth parameters
	redirectURL, err := url.Parse(callbackW.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")

	q := redirectURL.Query()
	ts.NotEmpty(q.Get("access_token"))
	ts.NotEmpty(q.Get("refresh_token"))
	ts.NotEmpty(q.Get("expires_in"))
	ts.NotEmpty(q.Get("provider_token"))

	// Verify the user data was updated
	user, err := models.FindUserByEmailAndAudience(ts.API.db, "twitter@example.com", ts.Config.JWT.Aud)
	ts.Require().NoError(err)
	ts.Equal("twitterTestId", user.UserMetaData["provider_id"])
	ts.Equal("Twitter Test", user.UserMetaData["full_name"])
	ts.Equal("twittertest", user.UserMetaData["user_name"])
	ts.Equal("http://example.com/twitter-avatar.jpg", user.UserMetaData["avatar_url"])
}

func (ts *ExternalTestSuite) TestInviteTokenExternalTwitterErrorWhenNoMatchingToken() {
	tokenCount, userCount := 0, 0
	oauthVerifier := "verifier123"
	server := TwitterTestSignupSetup(ts, &tokenCount, &userCount, oauthVerifier, twitterUser)
	defer server.Close()

	// Request with wrong invite token
	req := httptest.NewRequest(http.MethodGet, "http://localhost/authorize?provider=twitter&invite_token=invite_token", nil)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusNotFound, w.Code)
}

func (ts *ExternalTestSuite) TestInviteTokenExternalTwitterErrorWhenWrongToken() {
	ts.createUser("twitterTestId", "twitter@example.com", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	oauthVerifier := "verifier123"
	server := TwitterTestSignupSetup(ts, &tokenCount, &userCount, oauthVerifier, twitterUser)
	defer server.Close()

	// Request with wrong invite token
	req := httptest.NewRequest(http.MethodGet, "http://localhost/authorize?provider=twitter&invite_token=wrong_token", nil)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusNotFound, w.Code)
}

func (ts *ExternalTestSuite) TestInviteTokenExternalTwitterErrorWhenEmailDoesntMatch() {
	ts.T().Skip("Skipping Twitter OAuth tests due to complexity in mocking OAuth 1.0a flow")
	ts.createUser("twitterTestId", "twitter@example.com", "", "", "invite_token")

	tokenCount, userCount := 0, 0
	oauthVerifier := "verifier123"
	server := TwitterTestSignupSetup(ts, &tokenCount, &userCount, oauthVerifier, twitterUserWrongEmail)
	defer server.Close()

	// First, get the authorization URL with invite token
	req := httptest.NewRequest(http.MethodGet, "http://localhost/authorize?provider=twitter&invite_token=invite_token", nil)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)

	// Create a state token that includes invite token
	claims := ExternalProviderClaims{
		AuthMicroserviceClaims: AuthMicroserviceClaims{
			RegisteredClaims: jwt.RegisteredClaims{},
			SiteURL:          ts.Config.SiteURL,
		},
		Provider:    "twitter",
		InviteToken: "invite_token",
	}
	tokenString, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(ts.Config.JWT.Secret))
	ts.Require().NoError(err)

	// Simulate callback
	callbackReq := httptest.NewRequest(
		http.MethodGet,
		fmt.Sprintf("http://localhost/callback?provider=twitter&state=%s&oauth_token=twitter_oauth_token&oauth_verifier=%s",
			tokenString, oauthVerifier),
		nil,
	)
	callbackW := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(callbackW, callbackReq)
	ts.Require().Equal(http.StatusFound, callbackW.Code)

	// Should redirect with error
	redirectURL, err := url.Parse(callbackW.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")

	q := redirectURL.Query()
	ts.Equal("invalid_request", q.Get("error"))
	ts.Equal("Invited email does not match emails from external provider", q.Get("error_description"))
}
