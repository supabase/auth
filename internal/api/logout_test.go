package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
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

	project_id := uuid.Must(uuid.NewV4())
	// Create a project
	if err := ts.API.db.RawQuery(fmt.Sprintf("INSERT INTO auth.projects (id, name) VALUES ('%s', 'test_project')", project_id)).Exec(); err != nil {
		panic(err)
	}

	// Create the admin of the organization
	user, err := models.NewUser("", "admin@example.com", "test", ts.Config.JWT.Aud, nil, uuid.Nil, project_id)
	require.NoError(ts.T(), err, "Error making new user")
	require.NoError(ts.T(), ts.API.db.Create(user, "organization_id", "organization_role"), "Error creating user")

	// Create the organization
	organization_id := uuid.Must(uuid.FromString("123e4567-e89b-12d3-a456-426655440000"))
	if err := ts.API.db.RawQuery(fmt.Sprintf("INSERT INTO auth.organizations (id, name, project_id, admin_id) VALUES ('%s', 'test_organization', '%s', '%s')", organization_id, project_id, user.ID)).Exec(); err != nil {
		panic(err)
	}

	// Set the user as the admin of the organization
	if err := ts.API.db.RawQuery(fmt.Sprintf("UPDATE auth.users SET organization_id = '%s', organization_role='admin' WHERE id = '%s'", organization_id, user.ID)).Exec(); err != nil {
		panic(err)
	}

	u, err := models.NewUser("", "test@example.com", "password", ts.Config.JWT.Aud, nil, organization_id, uuid.Nil)
	require.NoError(ts.T(), err, "Error creating test user model")
	require.NoError(ts.T(), ts.API.db.Create(u, "project_id", "organization_role"), "Error saving new test user")

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
