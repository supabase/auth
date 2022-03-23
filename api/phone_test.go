package api

import (
	"context"
	"testing"

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
	u, err := models.NewUser(ts.instanceID, "", "password", ts.Config.JWT.Aud, nil)
	u.Phone = "123456789"
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
			phoneChangeOtp,
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
			case phoneChangeOtp:
				require.NotEmpty(ts.T(), u.PhoneChangeToken)
				require.NotEmpty(ts.T(), u.PhoneChangeSentAt)
			default:
			}
		})
	}
}
