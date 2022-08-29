package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt"
	"github.com/netlify/gotrue/conf"
	"github.com/netlify/gotrue/crypto"
	"github.com/netlify/gotrue/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type AdminTestSuite struct {
	suite.Suite
	User   *models.User
	API    *API
	Config *conf.GlobalConfiguration

	token string
}

func TestAdmin(t *testing.T) {
	api, config, err := setupAPIForTest()
	require.NoError(t, err)

	ts := &AdminTestSuite{
		API:    api,
		Config: config,
	}
	defer api.db.Close()

	suite.Run(t, ts)
}

func (ts *AdminTestSuite) SetupTest() {
	models.TruncateAll(ts.API.db)
	ts.Config.External.Email.Enabled = true
	claims := &GoTrueClaims{
		Role: "supabase_admin",
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(ts.Config.JWT.Secret))
	require.NoError(ts.T(), err, "Error generating admin jwt")
	ts.token = token
}

// TestAdminUsersUnauthorized tests API /admin/users route without authentication
func (ts *AdminTestSuite) TestAdminUsersUnauthorized() {
	req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	assert.Equal(ts.T(), http.StatusUnauthorized, w.Code)
}

// TestAdminUsers tests API /admin/users route
func (ts *AdminTestSuite) TestAdminUsers() {
	// Setup request
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	assert.Equal(ts.T(), "</admin/users?page=0>; rel=\"last\"", w.HeaderMap.Get("Link"))
	assert.Equal(ts.T(), "0", w.HeaderMap.Get("X-Total-Count"))
}

// TestAdminUsers tests API /admin/users route
func (ts *AdminTestSuite) TestAdminUsers_Pagination() {
	u, err := models.NewUser("12345678", "test1@example.com", "test", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err, "Error making new user")
	require.NoError(ts.T(), ts.API.db.Create(u), "Error creating user")

	u, err = models.NewUser("987654321", "test2@example.com", "test", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err, "Error making new user")
	require.NoError(ts.T(), ts.API.db.Create(u), "Error creating user")

	// Setup request
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/users?per_page=1", nil)

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	assert.Equal(ts.T(), "</admin/users?page=2&per_page=1>; rel=\"next\", </admin/users?page=2&per_page=1>; rel=\"last\"", w.HeaderMap.Get("Link"))
	assert.Equal(ts.T(), "2", w.HeaderMap.Get("X-Total-Count"))

	data := make(map[string]interface{})
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))
	for _, user := range data["users"].([]interface{}) {
		assert.NotEmpty(ts.T(), user)
	}
}

// TestAdminUsers tests API /admin/users route
func (ts *AdminTestSuite) TestAdminUsers_SortAsc() {
	u, err := models.NewUser("", "test1@example.com", "test", ts.Config.JWT.Aud, nil)
	u.CreatedAt = time.Now().Add(-time.Minute)
	require.NoError(ts.T(), err, "Error making new user")
	require.NoError(ts.T(), ts.API.db.Create(u), "Error creating user")

	u, err = models.NewUser("", "test2@example.com", "test", ts.Config.JWT.Aud, nil)
	u.CreatedAt = time.Now()
	require.NoError(ts.T(), err, "Error making new user")
	require.NoError(ts.T(), ts.API.db.Create(u), "Error creating user")

	// Setup request
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	qv := req.URL.Query()
	qv.Set("sort", "created_at asc")
	req.URL.RawQuery = qv.Encode()

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	data := struct {
		Users []*models.User `json:"users"`
		Aud   string         `json:"aud"`
	}{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))

	require.Len(ts.T(), data.Users, 2)
	assert.Equal(ts.T(), "test1@example.com", data.Users[0].GetEmail())
	assert.Equal(ts.T(), "test2@example.com", data.Users[1].GetEmail())
}

// TestAdminUsers tests API /admin/users route
func (ts *AdminTestSuite) TestAdminUsers_SortDesc() {
	u, err := models.NewUser("12345678", "test1@example.com", "test", ts.Config.JWT.Aud, nil)
	u.CreatedAt = time.Now().Add(-time.Minute)
	require.NoError(ts.T(), err, "Error making new user")
	require.NoError(ts.T(), ts.API.db.Create(u), "Error creating user")

	u, err = models.NewUser("987654321", "test2@example.com", "test", ts.Config.JWT.Aud, nil)
	u.CreatedAt = time.Now()
	require.NoError(ts.T(), err, "Error making new user")
	require.NoError(ts.T(), ts.API.db.Create(u), "Error creating user")

	// Setup request
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	data := struct {
		Users []*models.User `json:"users"`
		Aud   string         `json:"aud"`
	}{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))

	require.Len(ts.T(), data.Users, 2)
	assert.Equal(ts.T(), "test2@example.com", data.Users[0].GetEmail())
	assert.Equal(ts.T(), "test1@example.com", data.Users[1].GetEmail())
}

// TestAdminUsers tests API /admin/users route
func (ts *AdminTestSuite) TestAdminUsers_FilterEmail() {
	u, err := models.NewUser("", "test1@example.com", "test", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err, "Error making new user")
	require.NoError(ts.T(), ts.API.db.Create(u), "Error creating user")

	// Setup request
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/users?filter=test1", nil)

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	data := struct {
		Users []*models.User `json:"users"`
		Aud   string         `json:"aud"`
	}{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))

	require.Len(ts.T(), data.Users, 1)
	assert.Equal(ts.T(), "test1@example.com", data.Users[0].GetEmail())
}

// TestAdminUsers tests API /admin/users route
func (ts *AdminTestSuite) TestAdminUsers_FilterName() {
	u, err := models.NewUser("", "test1@example.com", "test", ts.Config.JWT.Aud, map[string]interface{}{"full_name": "Test User"})
	require.NoError(ts.T(), err, "Error making new user")
	require.NoError(ts.T(), ts.API.db.Create(u), "Error creating user")

	u, err = models.NewUser("", "test2@example.com", "test", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err, "Error making new user")
	require.NoError(ts.T(), ts.API.db.Create(u), "Error creating user")

	// Setup request
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/users?filter=User", nil)

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	data := struct {
		Users []*models.User `json:"users"`
		Aud   string         `json:"aud"`
	}{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))

	require.Len(ts.T(), data.Users, 1)
	assert.Equal(ts.T(), "test1@example.com", data.Users[0].GetEmail())
}

// TestAdminUserCreate tests API /admin/user route (POST)
func (ts *AdminTestSuite) TestAdminUserCreate() {
	cases := []struct {
		desc     string
		params   map[string]interface{}
		expected map[string]interface{}
	}{
		{
			desc: "With password",
			params: map[string]interface{}{
				"email":    "test1@example.com",
				"phone":    "123456789",
				"password": "test1",
			},
			expected: map[string]interface{}{
				"email":           "test1@example.com",
				"phone":           "123456789",
				"isAuthenticated": true,
			},
		},
		{
			desc: "Without password",
			params: map[string]interface{}{
				"email": "test2@example.com",
				"phone": "",
			},
			expected: map[string]interface{}{
				"email":           "test2@example.com",
				"phone":           "",
				"isAuthenticated": false,
			},
		},
		{
			desc: "With empty string password",
			params: map[string]interface{}{
				"email":    "test3@example.com",
				"phone":    "",
				"password": "",
			},
			expected: map[string]interface{}{
				"email":           "test3@example.com",
				"phone":           "",
				"isAuthenticated": false,
			},
		},
		{
			desc: "Ban created user",
			params: map[string]interface{}{
				"email":        "test4@example.com",
				"phone":        "",
				"password":     "test1",
				"ban_duration": "24h",
			},
			expected: map[string]interface{}{
				"email":           "test4@example.com",
				"phone":           "",
				"isAuthenticated": true,
			},
		},
	}

	for _, c := range cases {
		ts.Run(c.desc, func() {
			var buffer bytes.Buffer
			require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(c.params))

			// Setup request
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/admin/users", &buffer)

			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))
			ts.Config.External.Phone.Enabled = true

			ts.API.handler.ServeHTTP(w, req)
			require.Equal(ts.T(), http.StatusOK, w.Code)

			data := models.User{}
			require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))
			assert.Equal(ts.T(), c.expected["email"], data.GetEmail())
			assert.Equal(ts.T(), c.expected["phone"], data.GetPhone())
			assert.Equal(ts.T(), "email", data.AppMetaData["provider"])
			assert.Equal(ts.T(), []interface{}{"email"}, data.AppMetaData["providers"])

			u, err := models.FindUserByEmailAndAudience(ts.API.db, data.GetEmail(), ts.Config.JWT.Aud)
			require.NoError(ts.T(), err)

			var expectedPassword string
			if _, ok := c.params["password"]; ok {
				expectedPassword = fmt.Sprintf("%v", c.params["password"])
			}

			assert.Equal(ts.T(), c.expected["isAuthenticated"], u.Authenticate(expectedPassword))
		})
	}
}

// TestAdminUserGet tests API /admin/user route (GET)
func (ts *AdminTestSuite) TestAdminUserGet() {
	u, err := models.NewUser("12345678", "test1@example.com", "test", ts.Config.JWT.Aud, map[string]interface{}{"full_name": "Test Get User"})
	require.NoError(ts.T(), err, "Error making new user")
	require.NoError(ts.T(), ts.API.db.Create(u), "Error creating user")

	// Setup request
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/admin/users/%s", u.ID), nil)

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	data := make(map[string]interface{})
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))

	assert.Equal(ts.T(), data["email"], "test1@example.com")
	assert.NotNil(ts.T(), data["app_metadata"])
	assert.NotNil(ts.T(), data["user_metadata"])
	md := data["user_metadata"].(map[string]interface{})
	assert.Len(ts.T(), md, 1)
	assert.Equal(ts.T(), "Test Get User", md["full_name"])
}

// TestAdminUserUpdate tests API /admin/user route (UPDATE)
func (ts *AdminTestSuite) TestAdminUserUpdate() {
	u, err := models.NewUser("12345678", "test1@example.com", "test", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err, "Error making new user")
	require.NoError(ts.T(), ts.API.db.Create(u), "Error creating user")

	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"role": "testing",
		"app_metadata": map[string]interface{}{
			"roles": []string{"writer", "editor"},
		},
		"user_metadata": map[string]interface{}{
			"name": "David",
		},
		"ban_duration": "24h",
	}))

	// Setup request
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/admin/users/%s", u.ID), &buffer)

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	data := models.User{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))

	assert.Equal(ts.T(), "testing", data.Role)
	assert.NotNil(ts.T(), data.UserMetaData)
	assert.Equal(ts.T(), "David", data.UserMetaData["name"])

	assert.NotNil(ts.T(), data.AppMetaData)
	assert.Len(ts.T(), data.AppMetaData["roles"], 2)
	assert.Contains(ts.T(), data.AppMetaData["roles"], "writer")
	assert.Contains(ts.T(), data.AppMetaData["roles"], "editor")
	assert.NotNil(ts.T(), data.BannedUntil)
}

func (ts *AdminTestSuite) TestAdminUserUpdatePasswordFailed() {
	u, err := models.NewUser("12345678", "test1@example.com", "test", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err, "Error making new user")
	require.NoError(ts.T(), ts.API.db.Create(u), "Error creating user")

	var updateEndpoint = fmt.Sprintf("/admin/users/%s", u.ID)
	ts.Config.PasswordMinLength = 6
	ts.Run("Password doesn't meet minimum length", func() {
		var buffer bytes.Buffer
		require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
			"password": "",
		}))

		// Setup request
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, updateEndpoint, &buffer)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))

		ts.API.handler.ServeHTTP(w, req)
		require.Equal(ts.T(), http.StatusUnprocessableEntity, w.Code)
	})
}

func (ts *AdminTestSuite) TestAdminUserUpdateBannedUntilFailed() {
	u, err := models.NewUser("", "test1@example.com", "test", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err, "Error making new user")
	require.NoError(ts.T(), ts.API.db.Create(u), "Error creating user")

	var updateEndpoint = fmt.Sprintf("/admin/users/%s", u.ID)
	ts.Config.PasswordMinLength = 6
	ts.Run("Incorrect format for ban_duration", func() {
		var buffer bytes.Buffer
		require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
			"ban_duration": "24",
		}))

		// Setup request
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, updateEndpoint, &buffer)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))

		ts.API.handler.ServeHTTP(w, req)
		require.Equal(ts.T(), http.StatusBadRequest, w.Code)
	})
}

// TestAdminUserDelete tests API /admin/user route (DELETE)
func (ts *AdminTestSuite) TestAdminUserDelete() {
	u, err := models.NewUser("123456789", "test-delete@example.com", "test", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err, "Error making new user")
	require.NoError(ts.T(), ts.API.db.Create(u), "Error creating user")

	// Setup request
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/admin/users/%s", u.ID), nil)

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)
}

func (ts *AdminTestSuite) TestAdminUserCreateWithDisabledLogin() {
	var cases = []struct {
		desc         string
		customConfig *conf.GlobalConfiguration
		userData     map[string]interface{}
		expected     int
	}{
		{
			"Email Signups Disabled",
			&conf.GlobalConfiguration{
				JWT: ts.Config.JWT,
				External: conf.ProviderConfiguration{
					Email: conf.EmailProviderConfiguration{
						Enabled: false,
					},
				},
			},
			map[string]interface{}{
				"email":    "test1@example.com",
				"password": "test1",
			},
			http.StatusOK,
		},
		{
			"Phone Signups Disabled",
			&conf.GlobalConfiguration{
				JWT: ts.Config.JWT,
				External: conf.ProviderConfiguration{
					Phone: conf.PhoneProviderConfiguration{
						Enabled: false,
					},
				},
			},
			map[string]interface{}{
				"phone":    "123456789",
				"password": "test1",
			},
			http.StatusOK,
		},
		{
			"All Signups Disabled",
			&conf.GlobalConfiguration{
				JWT:           ts.Config.JWT,
				DisableSignup: true,
			},
			map[string]interface{}{
				"email":    "test2@example.com",
				"password": "test2",
			},
			http.StatusOK,
		},
	}

	for _, c := range cases {
		ts.Run(c.desc, func() {
			// Initialize user data
			var buffer bytes.Buffer
			require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(c.userData))

			// Setup request
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/admin/users", &buffer)
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))

			*ts.Config = *c.customConfig
			ts.API.handler.ServeHTTP(w, req)
			require.Equal(ts.T(), c.expected, w.Code)
		})
	}
}

// TestAdminUserDeleteRecoveryCodes tests API /admin/users/<user_id>/recovery_codes/
func (ts *AdminTestSuite) TestAdminUserDeleteRecoveryCodes() {
	// TODO(Joel): Test case where factor is unverified
	u, err := models.NewUser("123456789", "test-delete@example.com", "test", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err, "Error making new user")
	require.NoError(ts.T(), ts.API.db.Create(u), "Error creating user")

	f, err := models.NewFactor(u, "testSimpleName", "testFactorID", "totp", models.FactorVerifiedState, "secretkey")
	require.NoError(ts.T(), err, "Error creating test factor model")
	require.NoError(ts.T(), ts.API.db.Create(f), "Error saving new test factor")

	// Create batch of Recovery Codes
	for i := 0; i < models.NumRecoveryCodes; i++ {
		r, terr := models.NewRecoveryCode(u, crypto.SecureToken(models.RecoveryCodeLength))
		require.NoError(ts.T(), terr, "Error creating recovery code model")
		require.NoError(ts.T(), ts.API.db.Create(r), "Error creating recovery code")
	}

	// Setup request
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/admin/users/%s/recovery_codes", u.ID), nil)

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)
	// No valid recovery codes as recovery codes are generated in batches.
	rc, err := models.FindValidRecoveryCodesByUser(ts.API.db, u)
	require.Equal(ts.T(), 0, len(rc))
}

// TestAdminUserDeleteFactor tests API /admin/users/<user_id>/factor/<factor_id>/
func (ts *AdminTestSuite) TestAdminUserDeleteFactor() {
	// TODO(Joel): Test case where factor is unverified
	u, err := models.NewUser("123456789", "test-delete@example.com", "test", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err, "Error making new user")
	require.NoError(ts.T(), ts.API.db.Create(u), "Error creating user")

	f, err := models.NewFactor(u, "testSimpleName", "testFactorID", "totp", models.FactorVerifiedState, "secretkey")
	require.NoError(ts.T(), err, "Error creating test factor model")
	require.NoError(ts.T(), ts.API.db.Create(f), "Error saving new test factor")

	// Setup request
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/admin/users/%s/factor/%s/", u.ID, f.ID), nil)

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)

	_, err = models.FindFactorByFactorID(ts.API.db, f.ID)
	require.EqualError(ts.T(), err, models.FactorNotFoundError{}.Error())

}

// TestAdminUserGetFactor tests API /admin/user/<user_id>/factors/
func (ts *AdminTestSuite) TestAdminUserGetFactors() {
	u, err := models.NewUser("123456789", "test-delete@example.com", "test", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err, "Error making new user")
	require.NoError(ts.T(), ts.API.db.Create(u), "Error creating user")

	f, err := models.NewFactor(u, "testSimpleName", "testFactorID", "totp", models.FactorDisabledState, "secretkey")
	require.NoError(ts.T(), err, "Error creating test factor model")
	require.NoError(ts.T(), ts.API.db.Create(f), "Error saving new test factor")

	// Setup request
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/admin/users/%s/factor/", u.ID), nil)

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)
}

// TestAdminUserGetFactor tests API /admin/user/<user_id>/factors/<factor_id>
func (ts *AdminTestSuite) TestAdminUserGetFactor() {
	u, err := models.NewUser("123456789", "test-delete@example.com", "test", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err, "Error making new user")
	require.NoError(ts.T(), ts.API.db.Create(u), "Error creating user")

	f, err := models.NewFactor(u, "testSimpleName", "testFactorID", "totp", models.FactorDisabledState, "secretkey")
	require.NoError(ts.T(), err, "Error creating test factor model")
	require.NoError(ts.T(), ts.API.db.Create(f), "Error saving new test factor")

	// Setup request
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/admin/users/%s/factor/%s/", u.ID, f.ID), nil)

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)
}

func (ts *AdminTestSuite) TestAdminUserUpdateFactor() {
	u, err := models.NewUser("123456789", "test-delete@example.com", "test", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err, "Error making new user")
	require.NoError(ts.T(), ts.API.db.Create(u), "Error creating user")

	f, err := models.NewFactor(u, "testSimpleName", "testFactorID", "totp", models.FactorDisabledState, "secretkey")
	require.NoError(ts.T(), err, "Error creating test factor model")
	require.NoError(ts.T(), ts.API.db.Create(f), "Error saving new test factor")

	var cases = []struct {
		desc       string
		factorData map[string]interface{}
		expected   int
	}{
		{
			"Update Factor friendly name",
			map[string]interface{}{
				"friendly_name": "john",
			},
			http.StatusOK,
		},
		{
			"Update factor type",
			map[string]interface{}{
				"friendly_name": "john",
				"factor_type":   "totp",
				"factor_status": "unverified",
			},
			http.StatusOK,
		},
		{
			"Update Factor Status",
			map[string]interface{}{
				"factor_status": models.FactorVerifiedState,
			},
			http.StatusOK,
		},
	}

	// Initialize factor data
	for _, c := range cases {
		ts.Run(c.desc, func() {
			var buffer bytes.Buffer
			require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(c.factorData))
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/admin/users/%s/factor/%s/", u.ID, f.ID), &buffer)
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))
			ts.API.handler.ServeHTTP(w, req)
			require.Equal(ts.T(), http.StatusOK, w.Code)
		})
	}

}
