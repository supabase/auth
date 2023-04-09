package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/gotrue/internal/conf"
	"github.com/supabase/gotrue/internal/models"
)

type InviteTestSuite struct {
	suite.Suite
	API    *API
	Config *conf.GlobalConfiguration

	token string
}

func TestInvite(t *testing.T) {
	api, config, err := setupAPIForTest()
	require.NoError(t, err)

	ts := &InviteTestSuite{
		API:    api,
		Config: config,
	}
	defer api.db.Close()

	suite.Run(t, ts)
}

func (ts *InviteTestSuite) SetupTest() {
	models.TruncateAll(ts.API.db)

	// Setup response recorder with super admin privileges
	ts.token = ts.makeSuperAdmin("")
}

func (ts *InviteTestSuite) makeSuperAdmin(email string) string {
	// Cleanup existing user, if they already exist
	if u, _ := models.FindUserByEmailAndAudience(ts.API.db, email, ts.Config.JWT.Aud); u != nil {
		require.NoError(ts.T(), ts.API.db.Destroy(u), "Error deleting user")
	}

	u, err := models.NewUser("123456789", email, "test", ts.Config.JWT.Aud, map[string]interface{}{"full_name": "Test User"})
	require.NoError(ts.T(), err, "Error making new user")

	u.Role = "supabase_admin"

	var token string
	token, err = generateAccessToken(ts.API.db, u, nil, time.Second*time.Duration(ts.Config.JWT.Exp), ts.Config.JWT.Secret)

	require.NoError(ts.T(), err, "Error generating access token")

	p := jwt.Parser{ValidMethods: []string{jwt.SigningMethodHS256.Name}}
	_, err = p.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(ts.Config.JWT.Secret), nil
	})
	require.NoError(ts.T(), err, "Error parsing token")

	return token
}

func (ts *InviteTestSuite) TestInvite() {
	// Request body
	testCodeChallenge := "fe1cb900-47eb-42f0-8527-0f8da7ba19f8"
	cases := []struct {
		desc        string
		requestBody map[string]interface{}
		expected    int
	}{
		{
			desc: "(Implicit) invite user, valid",
			requestBody: map[string]interface{}{
				"email": "test@example.com",
				"data": map[string]interface{}{
					"a": 1,
				},
			},
			expected: http.StatusOK,
		},
		{
			desc: "(PKCE) invite user, valid",
			requestBody: map[string]interface{}{
				"email": "test@example.com",
				"data": map[string]interface{}{
					"a": 1,
				},
				"code_challenge_method": "s256",
				"code_challenge":        testCodeChallenge,
			},
			expected: http.StatusOK,
		},
		{
			desc: "(PKCE) invite user, invalid, missing code_challenge",
			requestBody: map[string]interface{}{
				"email":                 "test@example.com",
				"code_challenge_method": "s256",
			},
			expected: http.StatusBadRequest,
		},
		{
			desc: "(PKCE) invite user, missing code_challenge_method",
			requestBody: map[string]interface{}{
				"email":          "test@example.com",
				"code_challenge": testCodeChallenge,
			},
			expected: http.StatusBadRequest,
		},
	}

	for _, c := range cases {
		ts.Run(c.desc, func() {

			var buffer bytes.Buffer
			require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(c.requestBody))
			// Setup request
			req := httptest.NewRequest(http.MethodPost, "http://localhost/invite", &buffer)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))

			// Setup response recorder
			w := httptest.NewRecorder()

			ts.API.handler.ServeHTTP(w, req)
			assert.Equal(ts.T(), c.expected, w.Code)
		})
	}
}

func (ts *InviteTestSuite) TestInvitePKCE() {
	codeVerifier := "4a9505b9-0857-42bb-ab3c-098b4d28ddc2"
	codeChallenge := sha256.Sum256([]byte(codeVerifier))
	challenge := base64.RawURLEncoding.EncodeToString(codeChallenge[:])
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"email": "test@example.com",
		"data": map[string]interface{}{
			"a": 1,
		},
		"code_challenge_method": "s256",
		"code_challenge":        challenge,
	}))
	// Setup request
	req := httptest.NewRequest(http.MethodPost, "http://localhost/invite", &buffer)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))

	// Setup response recorder
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	u, err := models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)

	// Verify OTP
	requestUrl := fmt.Sprintf("http://localhost/verify?type=%v&token=%v", "invite", u.ConfirmationToken)
	req = httptest.NewRequest(http.MethodGet, requestUrl, &buffer)
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	assert.Equal(ts.T(), http.StatusSeeOther, w.Code)
	rURL, _ := w.Result().Location()

	u, err = models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	assert.True(ts.T(), u.IsConfirmed())

	f, err := url.ParseQuery(rURL.RawQuery)
	require.NoError(ts.T(), err)
	authCode := f.Get("code")
	assert.NotEmpty(ts.T(), authCode)
	// Extract token and sign in
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"code_verifier": codeVerifier,
		"auth_code":     authCode,
	}))
	req = httptest.NewRequest(http.MethodPost, "http://localhost/token?grant_type=pkce", &buffer)
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)
	verifyResp := &AccessTokenResponse{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&verifyResp))
	require.NotEmpty(ts.T(), verifyResp.Token)
}

func (ts *InviteTestSuite) TestInvite_WithoutAccess() {
	// Request body
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"email": "test@example.com",
		"data": map[string]interface{}{
			"a": 1,
		},
	}))

	// Setup request
	req := httptest.NewRequest(http.MethodPost, "http://localhost/invite", &buffer)
	req.Header.Set("Content-Type", "application/json")

	// Setup response recorder
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	assert.Equal(ts.T(), http.StatusUnauthorized, w.Code)
}

func (ts *InviteTestSuite) TestVerifyInvite() {
	cases := []struct {
		desc        string
		email       string
		requestBody map[string]interface{}
		expected    int
	}{
		{
			"Verify invite with password",
			"test@example.com",
			map[string]interface{}{
				"email":    "test@example.com",
				"type":     "invite",
				"token":    "asdf",
				"password": "testing",
			},
			http.StatusOK,
		},
		{
			"Verify invite with no password",
			"test1@example.com",
			map[string]interface{}{
				"email": "test1@example.com",
				"type":  "invite",
				"token": "asdf",
			},
			http.StatusOK,
		},
	}

	for _, c := range cases {
		ts.Run(c.desc, func() {
			user, err := models.NewUser("", c.email, "", ts.Config.JWT.Aud, nil)
			now := time.Now()
			user.InvitedAt = &now
			user.ConfirmationSentAt = &now
			user.EncryptedPassword = ""
			user.ConfirmationToken = fmt.Sprintf("%x", sha256.Sum224([]byte(c.email+c.requestBody["token"].(string))))
			require.NoError(ts.T(), err)
			require.NoError(ts.T(), ts.API.db.Create(user))

			// Find test user
			_, err = models.FindUserByEmailAndAudience(ts.API.db, c.email, ts.Config.JWT.Aud)
			require.NoError(ts.T(), err)

			// Request body
			var buffer bytes.Buffer
			require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(c.requestBody))

			// Setup request
			req := httptest.NewRequest(http.MethodPost, "http://localhost/verify", &buffer)
			req.Header.Set("Content-Type", "application/json")

			// Setup response recorder
			w := httptest.NewRecorder()

			ts.API.handler.ServeHTTP(w, req)

			assert.Equal(ts.T(), c.expected, w.Code, w.Body.String())
		})
	}
}

func (ts *InviteTestSuite) TestInviteExternalGitlab() {
	tokenCount, userCount := 0, 0
	code := "authcode"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			tokenCount++
			ts.Equal(code, r.FormValue("code"))
			ts.Equal("authorization_code", r.FormValue("grant_type"))
			ts.Equal(ts.Config.External.Gitlab.RedirectURI, r.FormValue("redirect_uri"))

			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"gitlab_token","expires_in":100000}`)
		case "/api/v4/user":
			userCount++
			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, `{"name":"Gitlab Test","email":"gitlab@example.com","avatar_url":"http://example.com/avatar","confirmed_at": "2020-01-01T00:00:00.000Z"}`)
		case "/api/v4/user/emails":
			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, `[]`)
		default:
			w.WriteHeader(http.StatusInternalServerError)
			ts.Fail("unknown gitlab oauth call %s", r.URL.Path)
		}
	}))
	defer server.Close()
	ts.Config.External.Gitlab.URL = server.URL

	// invite user
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(InviteParams{
		Email: "gitlab@example.com",
	}))
	req := httptest.NewRequest(http.MethodPost, "http://localhost/invite", &buffer)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusOK, w.Code)

	// Find test user
	user, err := models.FindUserByEmailAndAudience(ts.API.db, "gitlab@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)

	// get redirect url w/ state
	req = httptest.NewRequest(http.MethodGet, "http://localhost/authorize?provider=gitlab&invite_token="+user.ConfirmationToken, nil)
	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
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
	req = httptest.NewRequest(http.MethodGet, testURL.String(), nil)
	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)
	u, err = url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")

	// ensure redirect has #access_token=...
	v, err = url.ParseQuery(u.Fragment)
	ts.Require().NoError(err)
	ts.Require().Empty(v.Get("error_description"))
	ts.Require().Empty(v.Get("error"))

	ts.NotEmpty(v.Get("access_token"))
	ts.NotEmpty(v.Get("refresh_token"))
	ts.NotEmpty(v.Get("expires_in"))
	ts.Equal("bearer", v.Get("token_type"))

	ts.Equal(1, tokenCount)
	ts.Equal(1, userCount)

	// ensure user has been created with metadata
	user, err = models.FindUserByEmailAndAudience(ts.API.db, "gitlab@example.com", ts.Config.JWT.Aud)
	ts.Require().NoError(err)
	ts.Equal("Gitlab Test", user.UserMetaData["full_name"])
	ts.Equal("http://example.com/avatar", user.UserMetaData["avatar_url"])
	ts.Equal("gitlab", user.AppMetaData["provider"])
	ts.Equal([]interface{}{"gitlab"}, user.AppMetaData["providers"])
}

func (ts *InviteTestSuite) TestInviteExternalGitlab_MismatchedEmails() {
	tokenCount, userCount := 0, 0
	code := "authcode"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			tokenCount++
			ts.Equal(code, r.FormValue("code"))
			ts.Equal("authorization_code", r.FormValue("grant_type"))
			ts.Equal(ts.Config.External.Gitlab.RedirectURI, r.FormValue("redirect_uri"))

			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"gitlab_token","expires_in":100000}`)
		case "/api/v4/user":
			userCount++
			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, `{"name":"Gitlab Test","email":"gitlab+mismatch@example.com","avatar_url":"http://example.com/avatar","confirmed_at": "2020-01-01T00:00:00.000Z"}`)
		case "/api/v4/user/emails":
			w.Header().Add("Content-Type", "application/json")
			fmt.Fprint(w, `[]`)
		default:
			w.WriteHeader(500)
			ts.Fail("unknown gitlab oauth call %s", r.URL.Path)
		}
	}))
	defer server.Close()
	ts.Config.External.Gitlab.URL = server.URL

	// invite user
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(InviteParams{
		Email: "gitlab@example.com",
	}))
	req := httptest.NewRequest(http.MethodPost, "http://localhost/invite", &buffer)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusOK, w.Code)

	// Find test user
	user, err := models.FindUserByEmailAndAudience(ts.API.db, "gitlab@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)

	// get redirect url w/ state
	req = httptest.NewRequest(http.MethodGet, "http://localhost/authorize?provider=gitlab&invite_token="+user.ConfirmationToken, nil)
	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
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
	req = httptest.NewRequest(http.MethodGet, testURL.String(), nil)
	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)
	u, err = url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")

	// ensure redirect has #access_token=...
	v, err = url.ParseQuery(u.RawQuery)
	ts.Require().NoError(err, u.RawQuery)
	ts.Require().NotEmpty(v.Get("error_description"))
	ts.Require().Equal("invalid_request", v.Get("error"))
}
