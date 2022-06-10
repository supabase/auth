package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/conf"
	"github.com/netlify/gotrue/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type PhoneTestSuite struct {
	suite.Suite
	API    *API
	Config *conf.Configuration

	instanceID uuid.UUID
}

type TestSmsProvider struct {
	mock.Mock
}

func (t *TestSmsProvider) SendSms(phone string, message string) error {
	return nil
}

func TestPhone(t *testing.T) {
	api, config, instanceID, err := setupAPIForTestForInstance()
	require.NoError(t, err)

	ts := &PhoneTestSuite{
		API:        api,
		Config:     config,
		instanceID: instanceID,
	}
	defer api.db.Close()

	suite.Run(t, ts)
}

func (ts *PhoneTestSuite) SetupTest() {
	models.TruncateAll(ts.API.db)

	// Create user
	u, err := models.NewUser(ts.instanceID, "123456789", "", "password", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err, "Error creating test user model")
	require.NoError(ts.T(), ts.API.db.Create(u), "Error saving new test user")
}

func (ts *PhoneTestSuite) TestValidateE164Format() {
	isValid := ts.API.validateE164Format("0123456789")
	assert.Equal(ts.T(), false, isValid)
}

func (ts *PhoneTestSuite) TestFormatPhoneNumber() {
	actual := ts.API.formatPhoneNumber("+1 23456789 ")
	assert.Equal(ts.T(), "123456789", actual)
}

func (ts *PhoneTestSuite) TestSendPhoneConfirmation() {
	u, err := models.FindUserByPhoneAndAudience(ts.API.db, ts.instanceID, "123456789", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	ctx, err := WithInstanceConfig(context.Background(), ts.Config, ts.instanceID)
	require.NoError(ts.T(), err)
	cases := []struct {
		desc     string
		otpType  string
		expected error
	}{
		{
			"send confirmation otp",
			phoneConfirmationOtp,
			nil,
		},
		{
			"send phone_change otp",
			phoneChangeVerification,
			nil,
		},
		{
			"send recovery otp",
			phoneReauthenticationOtp,
			nil,
		},
		{
			"send invalid otp type ",
			"invalid otp type",
			internalServerError("invalid otp type"),
		},
	}

	for _, c := range cases {
		ts.Run(c.desc, func() {
			err = ts.API.sendPhoneConfirmation(ctx, ts.API.db, u, "123456789", c.otpType, &TestSmsProvider{})
			require.Equal(ts.T(), c.expected, err)
			u, err = models.FindUserByPhoneAndAudience(ts.API.db, ts.instanceID, "123456789", ts.Config.JWT.Aud)
			require.NoError(ts.T(), err)

			switch c.otpType {
			case phoneConfirmationOtp:
				require.NotEmpty(ts.T(), u.ConfirmationToken)
				require.NotEmpty(ts.T(), u.ConfirmationSentAt)
			case phoneChangeVerification:
				require.NotEmpty(ts.T(), u.PhoneChangeToken)
				require.NotEmpty(ts.T(), u.PhoneChangeSentAt)
			case phoneReauthenticationOtp:
				require.NotEmpty(ts.T(), u.ReauthenticationToken)
				require.NotEmpty(ts.T(), u.ReauthenticationSentAt)
			default:
			}
		})
	}
}

func (ts *PhoneTestSuite) TestMissingSmsProviderConfig() {
	u, err := models.FindUserByPhoneAndAudience(ts.API.db, ts.instanceID, "123456789", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)
	now := time.Now()
	u.PhoneConfirmedAt = &now
	require.NoError(ts.T(), ts.API.db.Update(u), "Error updating new test user")

	token, err := generateAccessToken(u, time.Second*time.Duration(ts.Config.JWT.Exp), ts.Config.JWT.Secret)
	require.NoError(ts.T(), err)

	cases := []struct {
		desc     string
		endpoint string
		method   string
		header   string
		body     map[string]string
		expected map[string]interface{}
	}{
		{
			"Signup",
			"/signup",
			http.MethodPost,
			"",
			map[string]string{
				"phone":    "1234567890",
				"password": "testpassword",
			},
			map[string]interface{}{
				"code":    http.StatusBadRequest,
				"message": "Error sending confirmation sms:",
			},
		},
		{
			"Sms OTP",
			"/otp",
			http.MethodPost,
			"",
			map[string]string{
				"phone": "123456789",
			},
			map[string]interface{}{
				"code":    http.StatusBadRequest,
				"message": "Error sending sms:",
			},
		},
		{
			"Phone change",
			"/user",
			http.MethodPut,
			token,
			map[string]string{
				"phone": "111111111",
			},
			map[string]interface{}{
				"code":    http.StatusBadRequest,
				"message": "Error sending sms:",
			},
		},
		{
			"Reauthenticate",
			"/reauthenticate",
			http.MethodGet,
			"",
			nil,
			map[string]interface{}{
				"code":    http.StatusBadRequest,
				"message": "Error sending sms:",
			},
		},
	}

	smsProviders := []string{"twilio", "messagebird", "textlocal", "vonage"}
	ts.Config.External.Phone.Enabled = true
	ts.Config.Sms.Twilio.AccountSid = ""
	ts.Config.Sms.Messagebird.AccessKey = ""
	ts.Config.Sms.Textlocal.ApiKey = ""
	ts.Config.Sms.Vonage.ApiKey = ""
	for _, c := range cases {
		for _, provider := range smsProviders {
			ts.Config.Sms.Provider = provider
			desc := fmt.Sprintf("[%v] %v", provider, c.desc)
			ts.Run(desc, func() {
				var buffer bytes.Buffer
				require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(c.body))

				req := httptest.NewRequest(c.method, "http://localhost"+c.endpoint, &buffer)
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

				w := httptest.NewRecorder()
				ts.API.handler.ServeHTTP(w, req)
				require.Equal(ts.T(), c.expected["code"], w.Code)

				body := w.Body.String()
				require.True(ts.T(), strings.Contains(body, c.expected["message"].(string)))
			})
		}
	}
}
