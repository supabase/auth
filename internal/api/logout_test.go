package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/gotrue/internal/conf"
	"github.com/supabase/gotrue/internal/models"
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
	t, err = generateAccessToken(ts.API.db, u, nil, &ts.Config.JWT)
	require.NoError(ts.T(), err)
	ts.token = t
}

func (ts *LogoutTestSuite) TestLogoutSuccess() {
	req := httptest.NewRequest(http.MethodPost, "http://localhost/logout", nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusNoContent, w.Code)

	accessTokenKey := fmt.Sprintf("%v-access-token", ts.Config.Cookie.Key)
	refreshTokenKey := fmt.Sprintf("%v-refresh-token", ts.Config.Cookie.Key)
	for _, c := range w.Result().Cookies() {
		if c.Name == accessTokenKey || c.Name == refreshTokenKey {
			require.Equal(ts.T(), "", c.Value)
		}
	}
}
