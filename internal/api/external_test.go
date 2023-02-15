package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/gotrue/internal/conf"
	"github.com/supabase/gotrue/internal/models"
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

	u, err := models.NewUser("", email, "test", ts.Config.JWT.Aud, map[string]interface{}{"provider_id": providerId, "full_name": name, "avatar_url": avatar})

	if confirmationToken != "" {
		u.ConfirmationToken = confirmationToken
	}
	ts.Require().NoError(err, "Error making new user")
	ts.Require().NoError(ts.API.db.Create(u), "Error creating user")

	i, err := models.NewIdentity(u, "email", map[string]interface{}{
		"sub":   u.ID.String(),
		"email": email,
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

	ts.Equal(1, tokenCount)
	ts.Equal(1, userCount)

	// ensure user has been created with metadata
	user, err := models.FindUserByEmailAndAudience(ts.API.db, email, ts.Config.JWT.Aud)
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

	// ensure user is nil
	user, err := models.FindUserByEmailAndAudience(ts.API.db, email, ts.Config.JWT.Aud)
	ts.Require().Error(err, "User not found")
	ts.Require().Nil(user)
}

// TestSignupExternalUnsupported tests API /authorize for an unsupported external provider
func (ts *ExternalTestSuite) TestSignupExternalUnsupported() {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/authorize?provider=external", nil)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Equal(w.Code, http.StatusBadRequest)
}
