package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/supabase/gotrue/internal/conf"
	"github.com/supabase/gotrue/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type OtpTestSuite struct {
	suite.Suite
	API    *API
	Config *conf.GlobalConfiguration
}

func TestOtp(t *testing.T) {
	api, config, err := setupAPIForTest()
	require.NoError(t, err)

	ts := &OtpTestSuite{
		API:    api,
		Config: config,
	}
	defer api.db.Close()

	suite.Run(t, ts)
}

func (ts *OtpTestSuite) SetupTest() {
	models.TruncateAll(ts.API.db)
}

func (ts *OtpTestSuite) TestOtp() {
	cases := []struct {
		desc     string
		params   OtpParams
		expected struct {
			code     int
			response map[string]interface{}
		}
	}{
		{
			desc: "Test Success Magiclink Otp",
			params: OtpParams{
				Email:      "test@example.com",
				CreateUser: true,
				Data: map[string]interface{}{
					"somedata": "metadata",
				},
			},
			expected: struct {
				code     int
				response map[string]interface{}
			}{
				http.StatusOK,
				make(map[string]interface{}),
			},
		},
		{
			desc: "Test Failure Pass Both Email & Phone",
			params: OtpParams{
				Email:      "test@example.com",
				Phone:      "123456789",
				CreateUser: true,
			},
			expected: struct {
				code     int
				response map[string]interface{}
			}{
				http.StatusBadRequest,
				map[string]interface{}{
					"code": float64(http.StatusBadRequest),
					"msg":  "Only an email address or phone number should be provided",
				},
			},
		},
	}

	for _, c := range cases {
		ts.Run(c.desc, func() {
			var buffer bytes.Buffer
			require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(c.params))

			req := httptest.NewRequest(http.MethodPost, "/otp", &buffer)
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()

			ts.API.handler.ServeHTTP(w, req)

			require.Equal(ts.T(), c.expected.code, w.Code)

			data := make(map[string]interface{})
			require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))

			// response should be empty
			assert.Equal(ts.T(), data, c.expected.response)
		})
	}
}

func (ts *OtpTestSuite) TestNoSignupsForOtp() {
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"email":       "newuser@example.com",
		"create_user": false,
	}))

	req := httptest.NewRequest(http.MethodPost, "/otp", &buffer)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)

	require.Equal(ts.T(), http.StatusBadRequest, w.Code)

	data := make(map[string]interface{})
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))

	// response should be empty
	assert.Equal(ts.T(), data, map[string]interface{}{
		"code": float64(http.StatusBadRequest),
		"msg":  "Signups not allowed for otp",
	})
}

func (ts *OtpTestSuite) TestSubsequentOtp() {
	ts.Config.SMTP.MaxFrequency = 0
	userEmail := "foo@example.com"
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"email": userEmail,
	}))

	req := httptest.NewRequest(http.MethodPost, "/otp", &buffer)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)

	require.Equal(ts.T(), http.StatusOK, w.Code)

	newUser, err := models.FindUserByEmailAndAudience(ts.API.db, userEmail, ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), newUser.ConfirmationToken)
	require.NotEmpty(ts.T(), newUser.ConfirmationSentAt)
	require.Empty(ts.T(), newUser.RecoveryToken)
	require.Empty(ts.T(), newUser.RecoverySentAt)
	require.Empty(ts.T(), newUser.EmailConfirmedAt)

	// since the signup process hasn't been completed,
	// subsequent requests for another magiclink should not create a recovery token
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"email": userEmail,
	}))

	req = httptest.NewRequest(http.MethodPost, "/otp", &buffer)
	req.Header.Set("Content-Type", "application/json")

	w = httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)

	require.Equal(ts.T(), http.StatusOK, w.Code)

	user, err := models.FindUserByEmailAndAudience(ts.API.db, userEmail, ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), user.ConfirmationToken)
	require.NotEmpty(ts.T(), user.ConfirmationSentAt)
	require.Empty(ts.T(), user.RecoveryToken)
	require.Empty(ts.T(), user.RecoverySentAt)
	require.Empty(ts.T(), user.EmailConfirmedAt)
}
