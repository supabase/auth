// +build integration

package sms_provider

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
)

// Integration test configuration
// These tests make real API calls to Plivo
// Set the following environment variables before running:
//   PLIVO_AUTH_ID      - Plivo Auth ID from console
//   PLIVO_AUTH_TOKEN   - Plivo Auth Token from console
//   PLIVO_SENDER_ID    - Plivo phone number to send from
//   PLIVO_TEST_PHONE   - Destination phone number for test SMS

func getTestConfig(t *testing.T) (authID, authToken, senderID, destination string) {
	authID = os.Getenv("PLIVO_AUTH_ID")
	authToken = os.Getenv("PLIVO_AUTH_TOKEN")
	senderID = os.Getenv("PLIVO_SENDER_ID")
	destination = os.Getenv("PLIVO_TEST_PHONE")

	if authID == "" || authToken == "" || senderID == "" || destination == "" {
		t.Skip("Skipping integration test: PLIVO_AUTH_ID, PLIVO_AUTH_TOKEN, PLIVO_SENDER_ID, and PLIVO_TEST_PHONE environment variables must be set")
	}

	return authID, authToken, senderID, destination
}

func TestPlivoIntegration_RealSMSSend(t *testing.T) {
	authID, authToken, senderID, destination := getTestConfig(t)

	config := conf.PlivoProviderConfiguration{
		AuthID:    authID,
		AuthToken: authToken,
		SenderID:  senderID,
	}

	provider, err := NewPlivoProvider(config)
	require.NoError(t, err, "Failed to create Plivo provider")

	// Generate a unique test message with timestamp
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	message := fmt.Sprintf("Supabase Auth Test OTP: 123456 (sent at %s)", timestamp)

	t.Run("SendSms_RealAPI", func(t *testing.T) {
		messageID, err := provider.SendSms(destination, message)

		if err != nil {
			t.Logf("Error sending SMS: %v", err)
		}

		assert.NoError(t, err, "SendSms should not return an error")
		assert.NotEmpty(t, messageID, "Message ID should be returned")

		if messageID != "" {
			t.Logf("SUCCESS: SMS sent with Message UUID: %s", messageID)
		}
	})

	t.Run("SendMessage_RealAPI_SMSChannel", func(t *testing.T) {
		otp := "654321"
		otpMessage := fmt.Sprintf("Your verification code is: %s", otp)

		messageID, err := provider.SendMessage(destination, otpMessage, SMSProvider, otp)

		if err != nil {
			t.Logf("Error sending message: %v", err)
		}

		assert.NoError(t, err, "SendMessage should not return an error")
		assert.NotEmpty(t, messageID, "Message ID should be returned")

		if messageID != "" {
			t.Logf("SUCCESS: Message sent via SendMessage with UUID: %s", messageID)
		}
	})
}

func TestPlivoIntegration_InvalidCredentials(t *testing.T) {
	_, _, senderID, destination := getTestConfig(t)

	config := conf.PlivoProviderConfiguration{
		AuthID:    "INVALID_AUTH_ID",
		AuthToken: "invalid_token",
		SenderID:  senderID,
	}

	provider, err := NewPlivoProvider(config)
	require.NoError(t, err, "Provider creation should succeed even with invalid credentials")

	t.Run("SendSms_InvalidAuth", func(t *testing.T) {
		_, err := provider.SendSms(destination, "Test message")

		assert.Error(t, err, "Should return error with invalid credentials")
		t.Logf("Expected error with invalid credentials: %v", err)
	})
}

func TestPlivoIntegration_ProviderValidation(t *testing.T) {
	authID, authToken, senderID, destination := getTestConfig(t)

	t.Run("ValidConfiguration", func(t *testing.T) {
		config := conf.PlivoProviderConfiguration{
			AuthID:    authID,
			AuthToken: authToken,
			SenderID:  senderID,
		}

		provider, err := NewPlivoProvider(config)

		assert.NoError(t, err)
		assert.NotNil(t, provider)
		assert.Equal(t, authID, provider.Config.AuthID)
		assert.Contains(t, provider.APIPath, authID)
		t.Logf("Provider API Path: %s", provider.APIPath)
	})

	t.Run("UnsupportedChannel", func(t *testing.T) {
		config := conf.PlivoProviderConfiguration{
			AuthID:    authID,
			AuthToken: authToken,
			SenderID:  senderID,
		}

		provider, _ := NewPlivoProvider(config)
		_, err := provider.SendMessage(destination, "Test", "whatsapp", "123456")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not supported")
	})
}
