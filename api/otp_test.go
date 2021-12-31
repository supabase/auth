package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/conf"
	"github.com/netlify/gotrue/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type OtpTestSuite struct {
	suite.Suite
	API    *API
	Config *conf.Configuration

	instanceID uuid.UUID
}

func TestOtp(t *testing.T) {
	api, config, instanceID, err := setupAPIForTestForInstance()
	require.NoError(t, err)

	ts := &OtpTestSuite{
		API:        api,
		Config:     config,
		instanceID: instanceID,
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
			"Test Success Magiclink Otp",
			OtpParams{
				Email:      "test@example.com",
				CreateUser: true,
			},
			struct {
				code     int
				response map[string]interface{}
			}{
				http.StatusOK,
				make(map[string]interface{}),
			},
		},
		{
			"Test Failure Pass Both Email & Phone",
			OtpParams{
				Email:      "test@example.com",
				Phone:      "123456789",
				CreateUser: true,
			},
			struct {
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
