package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
)

type AdminAuthCodeTestSuite struct {
	suite.Suite
	User   *models.User
	API    *API
	Config *conf.GlobalConfiguration

	token string
}

func TestAdminAuthCode(t *testing.T) {
	api, config, err := setupAPIForTest()
	require.NoError(t, err)

	ts := &AdminTestSuite{
		API:    api,
		Config: config,
	}
	defer api.db.Close()

	suite.Run(t, ts)
}

func (ts *AdminAuthCodeTestSuite) TestAdminIssueAuthCode() {
	user, err := models.NewUser("", "issueauthcode@example.com", "supersecret", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(user))

	tests := []struct {
		name            string
		body            map[string]interface{}
		expectedStatus  int
		expectedErrCode string
	}{
		{
			name: "Valid request - S256",
			body: map[string]interface{}{
				"id":                    user.ID.String(),
				"code_challenge_method": "S256",
				"code_challenge":        "valid-s256-code-challenge",
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Valid request - plain",
			body: map[string]interface{}{
				"id":                    user.ID.String(),
				"code_challenge_method": "plain",
				"code_challenge":        "some-plain-challenge",
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Missing ID",
			body: map[string]interface{}{
				"id":                    "",
				"code_challenge_method": "S256",
				"code_challenge":        "valid-challenge",
			},
			expectedStatus:  http.StatusBadRequest,
			expectedErrCode: apierrors.ErrorCodeValidationFailed, // from apierrors
		},
		{
			name: "User not found",
			body: map[string]interface{}{
				"id":                    uuid.Must(uuid.NewV4()).String(), // random user ID, not in DB
				"code_challenge_method": "S256",
				"code_challenge":        "valid-challenge",
			},
			expectedStatus:  http.StatusNotFound,
			expectedErrCode: apierrors.ErrorCodeUserNotFound,
		},
		{
			name: "Invalid user ID format",
			body: map[string]interface{}{
				"id":                    "not-a-valid-uuid",
				"code_challenge_method": "S256",
				"code_challenge":        "valid-challenge",
			},
			expectedStatus:  http.StatusBadRequest,
			expectedErrCode: apierrors.ErrorCodeValidationFailed,
		},
		{
			name: "Missing code_challenge_method",
			body: map[string]interface{}{
				"id":             user.ID.String(),
				"code_challenge": "some-challenge",
			},
			expectedStatus:  http.StatusBadRequest,
			expectedErrCode: apierrors.ErrorCodeValidationFailed,
		},
		{
			name: "Missing code_challenge",
			body: map[string]interface{}{
				"id":                    user.ID.String(),
				"code_challenge_method": "S256",
			},
			expectedStatus:  http.StatusBadRequest,
			expectedErrCode: apierrors.ErrorCodeValidationFailed,
		},
		{
			name: "Invalid code_challenge_method",
			body: map[string]interface{}{
				"id":                    user.ID.String(),
				"code_challenge_method": "invalid-method",
				"code_challenge":        "some-challenge",
			},
			expectedStatus:  http.StatusBadRequest,
			expectedErrCode: apierrors.ErrorCodeValidationFailed,
		},
	}

	for _, tc := range tests {
		ts.Run(tc.name, func() {
			var buf bytes.Buffer
			err := json.NewEncoder(&buf).Encode(tc.body)
			require.NoError(ts.T(), err)

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/admin/authcode", &buf)
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ts.token))

			ts.API.handler.ServeHTTP(w, req)
			require.Equal(ts.T(), tc.expectedStatus, w.Code, "Unexpected status code")

			if tc.expectedStatus >= 400 {
				var resp map[string]interface{}
				require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&resp))
				require.Equal(ts.T(), tc.expectedErrCode, resp["error_code"])
			} else {
				var resp map[string]string
				require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&resp))

				code, ok := resp["auth_code"]
				require.True(ts.T(), ok, "Response should contain `auth_code`")
				require.NotEmpty(ts.T(), code, "auth_code should not be empty")

				flowState, err := models.FindFlowStateByUserID(ts.API.db, user.ID.String(), models.OTP)
				require.NoError(ts.T(), err)

				require.Equal(ts.T(), tc.body["code_challenge_method"], flowState.CodeChallengeMethod)
				require.Equal(ts.T(), tc.body["code_challenge"], flowState.CodeChallenge)
				require.Equal(ts.T(), user.ID, flowState.UserID)
			}
		})
	}

	require.NoError(ts.T(), ts.API.db.Destroy(user))
}

func (ts *AdminTestSuite) TestAdminIssueAuthCodeUnauthorized() {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/authcode", nil)

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusUnauthorized, w.Code)
}
