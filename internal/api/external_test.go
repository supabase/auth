package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/tokens"
)

type ExternalTestSuite struct {
	suite.Suite
	API    *API
	Config *conf.GlobalConfiguration
}

func TestExternal(t *testing.T) {
	api, config, err := setupAPIForTest()
	require.NoError(t, err)

	ts := &ExternalTestSuite{
		API:    api,
		Config: config,
	}
	defer api.db.Close()

	suite.Run(t, ts)
}

func (ts *ExternalTestSuite) SetupTest() {
	ts.Config.DisableSignup = false
	ts.Config.Mailer.Autoconfirm = false

	models.TruncateAll(ts.API.db)
}

func (ts *ExternalTestSuite) createUser(providerId string, email string, name string, avatar string, confirmationToken string) (*models.User, error) {
	// Cleanup existing user, if they already exist
	if u, _ := models.FindUserByEmailAndAudience(ts.API.db, email, ts.Config.JWT.Aud); u != nil {
		require.NoError(ts.T(), ts.API.db.Destroy(u), "Error deleting user")
	}

	userData := map[string]interface{}{"provider_id": providerId, "full_name": name}
	if avatar != "" {
		userData["avatar_url"] = avatar
	}
	u, err := models.NewUser("", email, "test", ts.Config.JWT.Aud, userData)

	if confirmationToken != "" {
		u.ConfirmationToken = confirmationToken
	}
	ts.Require().NoError(err, "Error making new user")
	ts.Require().NoError(ts.API.db.Create(u), "Error creating user")

	if confirmationToken != "" {
		ts.Require().NoError(models.CreateOneTimeToken(ts.API.db, u.ID, email, u.ConfirmationToken, models.ConfirmationToken), "Error creating one-time confirmation/invite token")
	}

	i, err := models.NewIdentity(u, "email", map[string]interface{}{
		"sub":   u.ID.String(),
		"email": email,
	})
	ts.Require().NoError(err)
	ts.Require().NoError(ts.API.db.Create(i), "Error creating identity")

	return u, err
}

func (ts *ExternalTestSuite) createUserWithIdentity(providerType, providerId string, email string, name string, avatar string, confirmationToken string) (*models.User, error) {
	// Cleanup existing user, if they already exist
	if u, _ := models.FindUserByEmailAndAudience(ts.API.db, email, ts.Config.JWT.Aud); u != nil {
		require.NoError(ts.T(), ts.API.db.Destroy(u), "Error deleting user")
	}

	userData := map[string]interface{}{"provider_id": providerId, "full_name": name}
	if avatar != "" {
		userData["avatar_url"] = avatar
	}
	u, err := models.NewUser("", email, "test", ts.Config.JWT.Aud, userData)

	if confirmationToken != "" {
		u.ConfirmationToken = confirmationToken
	}
	ts.Require().NoError(err, "Error making new user")
	ts.Require().NoError(ts.API.db.Create(u), "Error creating user")

	if confirmationToken != "" {
		ts.Require().NoError(models.CreateOneTimeToken(ts.API.db, u.ID, email, u.ConfirmationToken, models.ConfirmationToken), "Error creating one-time confirmation/invite token")
	}

	if email != "" {
		i, err := models.NewIdentity(u, "email", map[string]interface{}{
			"sub":   u.ID.String(),
			"email": email,
		})
		ts.Require().NoError(err)
		ts.Require().NoError(ts.API.db.Create(i), "Error creating identity")
	}

	i, err := models.NewIdentity(u, providerType, map[string]interface{}{
		"sub": providerId,
	})
	ts.Require().NoError(err)
	ts.Require().NoError(ts.API.db.Create(i), "Error creating identity")

	return u, err
}

func performAuthorizationRequest(ts *ExternalTestSuite, provider string, inviteToken string) *httptest.ResponseRecorder {
	authorizeURL := "http://localhost/authorize?provider=" + provider
	if inviteToken != "" {
		authorizeURL = authorizeURL + "&invite_token=" + inviteToken
	}

	req := httptest.NewRequest(http.MethodGet, authorizeURL, nil)
	req.Header.Set("Referer", "https://example.netlify.com/admin")
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)

	return w
}

func performPKCEAuthorizationRequest(ts *ExternalTestSuite, provider, codeChallenge, codeChallengeMethod string) *httptest.ResponseRecorder {
	authorizeURL := "http://localhost/authorize?provider=" + provider
	if codeChallenge != "" {
		authorizeURL = authorizeURL + "&code_challenge=" + codeChallenge + "&code_challenge_method=" + codeChallengeMethod
	}

	req := httptest.NewRequest(http.MethodGet, authorizeURL, nil)
	req.Header.Set("Referer", "https://example.supabase.com/admin")
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	return w
}

func performPKCEAuthorization(ts *ExternalTestSuite, provider, code, codeChallenge, codeChallengeMethod string) *url.URL {
	w := performPKCEAuthorizationRequest(ts, provider, codeChallenge, codeChallengeMethod)
	ts.Require().Equal(http.StatusFound, w.Code)
	// Get code and state from the redirect
	u, err := url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")
	q := u.Query()
	state := q.Get("state")
	testURL, err := url.Parse("http://localhost/callback")
	ts.Require().NoError(err)
	v := testURL.Query()
	v.Set("code", code)
	v.Set("state", state)
	testURL.RawQuery = v.Encode()
	// Use the code to get a token
	req := httptest.NewRequest(http.MethodGet, testURL.String(), nil)
	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)
	u, err = url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")

	return u

}

func performAuthorization(ts *ExternalTestSuite, provider string, code string, inviteToken string) *url.URL {
	w := performAuthorizationRequest(ts, provider, inviteToken)
	ts.Require().Equal(http.StatusFound, w.Code)
	u, err := url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")
	q := u.Query()
	state := q.Get("state")

	// auth server callback
	testURL, err := url.Parse("http://localhost/callback")
	ts.Require().NoError(err)
	v := testURL.Query()
	v.Set("code", code)
	v.Set("state", state)
	testURL.RawQuery = v.Encode()
	req := httptest.NewRequest(http.MethodGet, testURL.String(), nil)
	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)
	u, err = url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")
	ts.Require().Equal("/admin", u.Path)

	return u
}

func assertAuthorizationSuccess(ts *ExternalTestSuite, u *url.URL, tokenCount int, userCount int, email string, name string, providerId string, avatar string) {
	// ensure redirect has #access_token=...
	v, err := url.ParseQuery(u.RawQuery)
	ts.Require().NoError(err)
	ts.Require().Empty(v.Get("error_description"))
	ts.Require().Empty(v.Get("error"))

	v, err = url.ParseQuery(u.Fragment)
	ts.Require().NoError(err)
	ts.NotEmpty(v.Get("access_token"))
	ts.NotEmpty(v.Get("refresh_token"))
	ts.NotEmpty(v.Get("expires_in"))
	ts.Equal("bearer", v.Get("token_type"))
	// Verify Supabase Auth identifier is present
	ts.Contains(v, "sb", "Fragment should contain Supabase Auth identifier 'sb'")

	ts.Equal(1, tokenCount)
	if userCount > -1 {
		ts.Equal(1, userCount)
	}

	// ensure user has been created with metadata
	var user *models.User
	if email != "" {
		user, err = models.FindUserByEmailAndAudience(ts.API.db, email, ts.Config.JWT.Aud)
	} else {
		identity := &models.Identity{}
		err = ts.API.db.Q().Where("provider_id = ?", providerId).First(identity)
		ts.Require().NoError(err)

		user, err = models.FindUserByID(ts.API.db, identity.UserID)
	}

	ts.Require().NoError(err)
	ts.Equal(providerId, user.UserMetaData["provider_id"])
	ts.Equal(name, user.UserMetaData["full_name"])
	if avatar == "" {
		ts.Equal(nil, user.UserMetaData["avatar_url"])
	} else {
		ts.Equal(avatar, user.UserMetaData["avatar_url"])
	}
}

func assertAuthorizationFailure(ts *ExternalTestSuite, u *url.URL, errorDescription string, errorType string, email string) {
	// ensure new sign ups error
	v, err := url.ParseQuery(u.RawQuery)
	ts.Require().NoError(err)
	ts.Require().Equal(errorDescription, v.Get("error_description"))
	ts.Require().Equal(errorType, v.Get("error"))

	v, err = url.ParseQuery(u.Fragment)
	ts.Require().NoError(err)
	ts.Empty(v.Get("access_token"))
	ts.Empty(v.Get("refresh_token"))
	ts.Empty(v.Get("expires_in"))
	ts.Empty(v.Get("token_type"))
	// Verify Supabase Auth identifier is present even in error responses
	ts.Contains(v, "sb", "Fragment should contain Supabase Auth identifier 'sb' even in errors")

	// ensure user is nil
	user, err := models.FindUserByEmailAndAudience(ts.API.db, email, ts.Config.JWT.Aud)
	ts.Require().Error(err, "User not found")
	ts.Require().Nil(user)
}

// assertValidOAuthState verifies that the state parameter is a valid UUID
// and that a corresponding flow_state record exists in the database with the correct provider.
func assertValidOAuthState(ts *ExternalTestSuite, state string, expectedProvider string) {
	ts.Require().NotEmpty(state, "state should not be empty")

	// Verify state is a valid UUID
	stateUUID, err := uuid.FromString(state)
	require.NoError(ts.T(), err, "state should be a valid UUID")
	require.NotEqual(ts.T(), uuid.Nil, stateUUID, "state UUID should not be nil")

	// Verify flow state exists in database with correct provider
	flowState, err := models.FindFlowStateByID(ts.API.db, stateUUID.String())
	require.NoError(ts.T(), err, "flow state should exist in database")
	ts.Equal(expectedProvider, flowState.ProviderType, "flow state provider should match")
}

// TestSignupExternalUnsupported tests API /authorize for an unsupported external provider
func (ts *ExternalTestSuite) TestSignupExternalUnsupported() {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/authorize?provider=external", nil)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Equal(w.Code, http.StatusBadRequest)
}

func (ts *ExternalTestSuite) TestRedirectErrorsShouldPreserveParams() {
	// Request with invalid external provider
	req := httptest.NewRequest(http.MethodGet, "http://localhost/authorize?provider=external", nil)
	w := httptest.NewRecorder()
	cases := []struct {
		Desc         string
		RedirectURL  string
		QueryParams  []string
		ErrorMessage string
	}{
		{
			Desc:         "Should preserve redirect query params on error",
			RedirectURL:  "http://example.com/path?paramforpreservation=value2",
			QueryParams:  []string{"paramforpreservation"},
			ErrorMessage: "invalid_request",
		},
		{
			Desc:         "Error param should be overwritten",
			RedirectURL:  "http://example.com/path?error=abc",
			QueryParams:  []string{"error"},
			ErrorMessage: "invalid_request",
		},
	}
	for _, c := range cases {
		parsedURL, err := url.Parse(c.RedirectURL)
		require.Equal(ts.T(), err, nil)

		redirectErrors(ts.API.internalExternalProviderCallback, w, req, parsedURL)

		parsedParams, err := url.ParseQuery(parsedURL.RawQuery)
		require.Equal(ts.T(), err, nil)

		// An error and description should be returned
		expectedQueryParams := append(c.QueryParams, "error", "error_description")

		for _, expectedQueryParam := range expectedQueryParams {
			val, exists := parsedParams[expectedQueryParam]
			require.True(ts.T(), exists)
			if expectedQueryParam == "error" {
				require.Equal(ts.T(), val[0], c.ErrorMessage)
			}
		}
	}
}

// setupGenericOAuthServer creates a mock OAuth server for testing state format handling.
// It handles token exchange and user info endpoints for mock GitHub provider.
func setupGenericOAuthServer(ts *ExternalTestSuite, code string) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/oauth/access_token":
			ts.Equal(code, r.FormValue("code"))
			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"test_token","expires_in":100000}`)
		case "/api/v3/user":
			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, `{"id":123,"name":"Test User","avatar_url":"http://example.com/avatar"}`)
		case "/api/v3/user/emails":
			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, `[{"email":"test@example.com","primary":true,"verified":true}]`)
		default:
			w.WriteHeader(500)
			ts.Fail("unknown oauth call %s", r.URL.Path)
		}
	}))
	ts.Config.External.Github.URL = server.URL
	return server
}

// TestOAuthState_BackwardCompatibleJWT tests that the callback endpoint
// still accepts the legacy JWT state format for backward compatibility during migration.
func (ts *ExternalTestSuite) TestOAuthState_BackwardCompatibleJWT() {
	code := "authcode"
	server := setupGenericOAuthServer(ts, code)
	defer server.Close()

	// Create a legacy JWT state token manually
	claims := &ExternalProviderClaims{
		AuthMicroserviceClaims: AuthMicroserviceClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				Issuer:    ts.Config.JWT.Issuer,
			},
		},
		Provider:      "github",
		Referrer:      "https://example.com/admin",
		EmailOptional: false,
	}

	jwtState, err := tokens.SignJWT(&ts.Config.JWT, claims)
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), jwtState)

	testURL, err := url.Parse("http://localhost/callback")
	require.NoError(ts.T(), err)
	v := testURL.Query()
	v.Set("code", code)
	v.Set("state", jwtState)
	testURL.RawQuery = v.Encode()

	req := httptest.NewRequest(http.MethodGet, testURL.String(), nil)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)

	ts.Require().Equal(http.StatusFound, w.Code)
	u, err := url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")
	ts.Require().Equal("/admin", u.Path)

	fragment, err := url.ParseQuery(u.Fragment)
	ts.Require().NoError(err)
	ts.NotEmpty(fragment.Get("access_token"), "should have access_token")
	ts.NotEmpty(fragment.Get("refresh_token"), "should have refresh_token")

	user, err := models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	require.NotNil(ts.T(), user)
}

// TestOAuthState_MigrationScenario tests that both UUID and JWT state formats
// can be processed during the migration period.
func (ts *ExternalTestSuite) TestOAuthState_MigrationScenario() {
	code := "authcode"
	server := setupGenericOAuthServer(ts, code)
	defer server.Close()

	ts.Run("NewUUIDFormat", func() {
		// Use the standard authorization flow which now generates UUID state
		w := performAuthorizationRequest(ts, "github", "")
		ts.Require().Equal(http.StatusFound, w.Code)
		u, err := url.Parse(w.Header().Get("Location"))
		ts.Require().NoError(err)

		state := u.Query().Get("state")
		ts.Require().NotEmpty(state)

		// Verify state is a valid UUID
		stateUUID, err := uuid.FromString(state)
		require.NoError(ts.T(), err, "state should be a valid UUID")
		require.NotEqual(ts.T(), uuid.Nil, stateUUID)

		// Complete the callback
		testURL, err := url.Parse("http://localhost/callback")
		require.NoError(ts.T(), err)
		v := testURL.Query()
		v.Set("code", code)
		v.Set("state", state)
		testURL.RawQuery = v.Encode()

		req := httptest.NewRequest(http.MethodGet, testURL.String(), nil)
		w = httptest.NewRecorder()
		ts.API.handler.ServeHTTP(w, req)

		ts.Require().Equal(http.StatusFound, w.Code)
		resultURL, err := url.Parse(w.Header().Get("Location"))
		ts.Require().NoError(err)

		fragment, err := url.ParseQuery(resultURL.Fragment)
		ts.Require().NoError(err)
		ts.NotEmpty(fragment.Get("access_token"), "UUID state should result in access_token")
	})

	// Clean up user for next test
	user, _ := models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	if user != nil {
		require.NoError(ts.T(), ts.API.db.Destroy(user))
	}

	ts.Run("LegacyJWTFormat", func() {
		// Create a legacy JWT state
		claims := &ExternalProviderClaims{
			AuthMicroserviceClaims: AuthMicroserviceClaims{
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
					IssuedAt:  jwt.NewNumericDate(time.Now()),
					Issuer:    ts.Config.JWT.Issuer,
				},
			},
			Provider: "github",
			Referrer: "https://example.com/admin",
		}

		jwtState, err := tokens.SignJWT(&ts.Config.JWT, claims)
		require.NoError(ts.T(), err)

		// Verify state is NOT a UUID (it's a JWT)
		_, uuidErr := uuid.FromString(jwtState)
		require.Error(ts.T(), uuidErr, "JWT state should not be parseable as UUID")

		// Complete the callback with JWT state
		testURL, err := url.Parse("http://localhost/callback")
		require.NoError(ts.T(), err)
		v := testURL.Query()
		v.Set("code", code)
		v.Set("state", jwtState)
		testURL.RawQuery = v.Encode()

		req := httptest.NewRequest(http.MethodGet, testURL.String(), nil)
		w := httptest.NewRecorder()
		ts.API.handler.ServeHTTP(w, req)

		ts.Require().Equal(http.StatusFound, w.Code)
		resultURL, err := url.Parse(w.Header().Get("Location"))
		ts.Require().NoError(err)

		fragment, err := url.ParseQuery(resultURL.Fragment)
		ts.Require().NoError(err)
		ts.NotEmpty(fragment.Get("access_token"), "JWT state should also result in access_token")
	})
}
