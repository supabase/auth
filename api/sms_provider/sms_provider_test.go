package sms_provider

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/netlify/gotrue/conf"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

var handleApiRequest func(*http.Request) (*http.Response, error)

type SmsProviderTestSuite struct {
	suite.Suite
	Config *conf.GlobalConfiguration
	Client HttpClient
}

type MockHttpClient struct {
	mock.Mock
}

func (m *MockHttpClient) Do(req *http.Request) (*http.Response, error) {
	return handleApiRequest(req)
}

func TestSmsProvider(t *testing.T) {

	ts := &SmsProviderTestSuite{
		Config: &conf.GlobalConfiguration{
			Sms: conf.SmsProviderConfiguration{
				Twilio: conf.TwilioProviderConfiguration{
					AccountSid:        "test_account_sid",
					AuthToken:         "test_auth_token",
					MessageServiceSid: "test_message_service_id",
				},
			},
		},
		Client: &MockHttpClient{},
	}
	suite.Run(t, ts)
}

func (ts *SmsProviderTestSuite) TestTwilioSendSms() {
	twilioProvider, err := NewTwilioProvider(ts.Config.Sms.Twilio)
	require.NoError(ts.T(), err)

	client = ts.Client

	handleApiRequest = func(req *http.Request) (*http.Response, error) {
		// check authorization header
		require.Contains(ts.T(), req.Header, "Authorization")

		// check request body sent
		require.NoError(ts.T(), req.ParseForm())
		require.Contains(ts.T(), req.Form, "To")
		require.Contains(ts.T(), req.Form, "Channel")
		require.Contains(ts.T(), req.Form, "From")
		require.Contains(ts.T(), req.Form, "Body")

		b, err := json.Marshal(&SmsStatus{
			To:     req.Form["To"][0],
			From:   req.Form["From"][0],
			Status: "sent",
			Body:   req.Form["Body"][0],
		})
		require.NoError(ts.T(), err)
		respBody := io.NopCloser(bytes.NewReader(b))

		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       respBody,
		}, nil
	}

	err = twilioProvider.SendSms("123456789", "This is a test message")
	require.NoError(ts.T(), err)
}
