package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
)

type LogoutTestSuite struct {
	suite.Suite
	API    *API
	Config *conf.GlobalConfiguration
	token  string
}

func TestLogout(t *testing.T) {
	api, config, err := setupAPIForTest()
	require.NoError(t, err)

	ts := &LogoutTestSuite{
		API:    api,
		Config: config,
	}
	defer api.db.Close()

	suite.Run(t, ts)
}

func (ts *LogoutTestSuite) SetupTest() {
	models.TruncateAll(ts.API.db)

	u, err := models.NewUser("", "test@example.com", "password", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err, "Error creating test user model")
	require.NoError(ts.T(), ts.API.db.Create(u), "Error saving new test user")

	// generate access token to use for logout
	var t string
	s, err := models.NewSession(u.ID, nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(s))

	req := httptest.NewRequest(http.MethodPost, "/token?grant_type=password", nil)
	t, _, err = ts.API.generateAccessToken(req, ts.API.db, u, &s.ID, models.PasswordGrant)
	require.NoError(ts.T(), err)
	ts.token = t
}

func (ts *LogoutTestSuite) TestLogoutSuccess() {
	for _, scope := range []string{"", "global", "local", "others"} {
		ts.SetupTest()

		reqURL, err := url.ParseRequestURI("http://localhost/logout")
		require.NoError(ts.T(), err)

		if scope != "" {
			query := reqURL.Query()
			query.Set("scope", scope)
			reqURL.RawQuery = query.Encode()
		}

		req := httptest.NewRequest(http.MethodPost, reqURL.String(), nil)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))
		w := httptest.NewRecorder()

		ts.API.handler.ServeHTTP(w, req)
		require.Equal(ts.T(), http.StatusNoContent, w.Code)
	}
}

func (ts *LogoutTestSuite) TestLogoutScopes() {
	type sess struct {
		id      uuid.UUID
		refresh string
		access  string
	}

	newUser := func(email string) *models.User {
		u, err := models.NewUser("", email, "password", ts.Config.JWT.Aud, nil)
		require.NoError(ts.T(), err)
		require.NoError(ts.T(), ts.API.db.Create(u))
		return u
	}

	newSess := func(u *models.User) sess {
		rt, err := models.GrantAuthenticatedUser(ts.API.db, u, models.GrantParams{})
		require.NoError(ts.T(), err)

		req := httptest.NewRequest(http.MethodPost, "/token?grant_type=password", nil)
		access, _, err := ts.API.generateAccessToken(req, ts.API.db, u, rt.SessionId, models.PasswordGrant)
		require.NoError(ts.T(), err)

		return sess{id: *rt.SessionId, refresh: rt.Token, access: access}
	}

	// setup creates 3 sessions for one user and 1 session for another user.
	setup := func() ([]sess, sess) {
		models.TruncateAll(ts.API.db)
		u := newUser("test@example.com")
		other := newUser("other@example.com")
		return []sess{newSess(u), newSess(u), newSess(u)}, newSess(other)
	}

	logout := func(token, scope string) int {
		req := httptest.NewRequest(http.MethodPost, "http://localhost/logout?"+url.Values{"scope": {scope}}.Encode(), nil)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
		w := httptest.NewRecorder()
		ts.API.handler.ServeHTTP(w, req)
		return w.Code
	}

	assertAlive := func(s sess) {
		_, err := models.FindSessionByID(ts.API.db, s.id, false)
		require.NoError(ts.T(), err, "session %s should still exist", s.id)
	}

	assertGone := func(s sess) {
		_, err := models.FindSessionByID(ts.API.db, s.id, false)
		require.ErrorIs(ts.T(), err, models.SessionNotFoundError{}, "session %s should be gone", s.id)

		// refresh token no longer works
		var body bytes.Buffer
		require.NoError(ts.T(), json.NewEncoder(&body).Encode(map[string]string{"refresh_token": s.refresh}))
		req := httptest.NewRequest(http.MethodPost, "http://localhost/token?grant_type=refresh_token", &body)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		ts.API.handler.ServeHTTP(w, req)
		require.Equal(ts.T(), http.StatusBadRequest, w.Code)

		// access token no longer works
		req = httptest.NewRequest(http.MethodGet, "http://localhost/user", nil)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.access))
		w = httptest.NewRecorder()
		ts.API.handler.ServeHTTP(w, req)
		require.Equal(ts.T(), http.StatusForbidden, w.Code)

		var resp struct {
			ErrorCode string `json:"error_code"`
		}
		require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&resp))
		require.Equal(ts.T(), apierrors.ErrorCodeSessionNotFound, resp.ErrorCode)
	}

	cases := []struct {
		scope string
		gone  []int
		alive []int
	}{
		{scope: "local", gone: []int{0}, alive: []int{1, 2}},
		{scope: "others", gone: []int{1, 2}, alive: []int{0}},
		{scope: "global", gone: []int{0, 1, 2}},
		{scope: "", gone: []int{0, 1, 2}},
	}

	for _, c := range cases {
		ts.Run("scope="+c.scope, func() {
			mine, other := setup()

			// always log out using session 1's token
			require.Equal(ts.T(), http.StatusNoContent, logout(mine[0].access, c.scope))

			for _, i := range c.gone {
				assertGone(mine[i])
			}
			for _, i := range c.alive {
				assertAlive(mine[i])
			}
			assertAlive(other)
		})
	}

	ts.Run("scope=bogus", func() {
		mine, _ := setup()
		require.Equal(ts.T(), http.StatusBadRequest, logout(mine[0].access, "bogus"))
	})
}
