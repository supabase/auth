package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/hooks"

	"gopkg.in/h2non/gock.v1"
)

var handleApiRequest func(*http.Request) (*http.Response, error)

type HooksTestSuite struct {
	suite.Suite
	API    *API
	Config *conf.GlobalConfiguration
}

type MockHttpClient struct {
	mock.Mock
}

func (m *MockHttpClient) Do(req *http.Request) (*http.Response, error) {
	return handleApiRequest(req)
}

func TestHooks(t *testing.T) {
	api, config, err := setupAPIForTest()
	require.NoError(t, err)

	ts := &HooksTestSuite{
		API:    api,
		Config: config,
	}
	defer api.db.Close()

	suite.Run(t, ts)
}

func (ts *HooksTestSuite) TestRunHTTPHook() {
	defer gock.OffAll()

	input := hooks.SendSMSInput{
		UserID: uuid.Must(uuid.NewV4()),
		Phone:  "1234567890",
		OTP:    "123456",
	}
	successOutput := hooks.SendSMSOutput{Success: true}
	testURL := "http://localhost:54321/functions/v1/custom-sms-sender"
	ts.Config.Hook.SendSMS.URI = testURL

	testCases := []struct {
		description  string
		mockResponse interface{}
		status       int
		expectError  bool
	}{
		{
			description:  "Successful Post request with delay",
			mockResponse: successOutput,
			status:       http.StatusOK,
			expectError:  false,
		},
		{
			description: "Too many requests without retry header should not retry",
			status:      http.StatusUnprocessableEntity,
			expectError: true,
		},
	}

	for _, tc := range testCases {
		ts.Run(tc.description, func() {
			if tc.status == http.StatusOK {
				gock.New(ts.Config.Hook.SendSMS.URI).
					Post("/").
					MatchType("json").
					Reply(tc.status).
					JSON(tc.mockResponse).SetHeader("content-length", "21")
			} else {
				gock.New(ts.Config.Hook.SendSMS.URI).
					Post("/").
					MatchType("json").
					Reply(tc.status).
					JSON(tc.mockResponse)

			}

			var output hooks.SendSMSOutput
			req, _ := http.NewRequest("POST", ts.Config.Hook.SendSMS.URI, nil)
			ctx := req.Context()
			body, err := ts.API.runHTTPHook(ctx, req, ts.Config.Hook.SendSMS, &input, &output)

			if !tc.expectError {
				require.NoError(ts.T(), err)
				if body != nil {
					require.NoError(ts.T(), json.Unmarshal(body, &output))
					require.True(ts.T(), output.Success)
				}
			} else {
				require.Error(ts.T(), err)
			}
			require.True(ts.T(), gock.IsDone())
		})
	}
}

func (ts *HooksTestSuite) TestShouldRetryWithRetryAfterHeader() {
	defer gock.OffAll()

	input := hooks.SendSMSInput{
		UserID: uuid.Must(uuid.NewV4()),
		Phone:  "1234567890",
		OTP:    "123456",
	}
	successOutput := hooks.SendSMSOutput{Success: true}
	testURL := "http://localhost:54321/functions/v1/custom-sms-sender"
	ts.Config.Hook.SendSMS.URI = testURL

	gock.New(testURL).
		Post("/").
		MatchType("json").
		Reply(http.StatusTooManyRequests).
		SetHeader("retry-after", "true").SetHeader("content-length", "21")

	// Simulate an additional response for the retry attempt
	gock.New(testURL).
		Post("/").
		MatchType("json").
		Reply(http.StatusOK).
		JSON(successOutput).SetHeader("content-length", "21")

	var output hooks.SendSMSOutput

	// Simulate the original HTTP request which triggered the hook
	req, err := http.NewRequest("POST", "http://localhost:9998/otp", nil)
	require.NoError(ts.T(), err)
	ctx := req.Context()

	body, err := ts.API.runHTTPHook(ctx, req, ts.Config.Hook.SendSMS, &input, &output)
	require.NoError(ts.T(), err)

	err = json.Unmarshal(body, &output)
	require.NoError(ts.T(), err, "Unmarshal should not fail")
	require.True(ts.T(), output.Success, "Expected success on retry")

	// Ensure that all expected HTTP interactions (mocks) have been called
	require.True(ts.T(), gock.IsDone(), "Expected all mocks to have been called including retry")
}
