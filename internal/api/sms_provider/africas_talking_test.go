package sms_provider

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
)

func TestAfricasTalkingProvider_Validate(t *testing.T) {
	t.Run("missing api key", func(t *testing.T) {
		config := conf.AfricasTalkingProviderConfiguration{
			Username: "sandbox",
		}
		_, err := NewAfricasTalkingProvider(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "API key")
	})

	t.Run("missing username", func(t *testing.T) {
		config := conf.AfricasTalkingProviderConfiguration{
			APIKey: "test_key",
		}
		_, err := NewAfricasTalkingProvider(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "username")
	})

	t.Run("valid sandbox config", func(t *testing.T) {
		config := conf.AfricasTalkingProviderConfiguration{
			APIKey:   "test_key",
			Username: "sandbox",
		}
		provider, err := NewAfricasTalkingProvider(config)
		require.NoError(t, err)
		assert.NotNil(t, provider)

		atProvider := provider.(*AfricasTalkingProvider)
		assert.Equal(t, ATSandboxEndpoint, atProvider.APIEndpoint)
	})

	t.Run("valid production config", func(t *testing.T) {
		config := conf.AfricasTalkingProviderConfiguration{
			APIKey:   "live_key",
			Username: "myapp",
		}
		provider, err := NewAfricasTalkingProvider(config)
		require.NoError(t, err)

		atProvider := provider.(*AfricasTalkingProvider)
		assert.Equal(t, ATProductionEndpoint, atProvider.APIEndpoint)
	})
}

func TestAfricasTalkingProvider_SendMessage(t *testing.T) {
	// Mock Africa's Talking API server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify required headers
		assert.Equal(t, "test_api_key", r.Header.Get("apiKey"))
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
		assert.Equal(t, "application/json", r.Header.Get("Accept"))

		// Parse form body
		require.NoError(t, r.ParseForm())
		assert.Equal(t, "sandbox", r.FormValue("username"))
		assert.Equal(t, "+254712345678", r.FormValue("to"))
		assert.NotEmpty(t, r.FormValue("message"))

		// Return a successful AT response
		resp := ATResponse{
			SMSMessageData: ATSMSMessageData{
				Message: "Sent to 1/1 Total Cost: KES 0.8000",
				Recipients: []ATRecipient{
					{
						StatusCode: 101,
						Number:     "+254712345678",
						Status:     "Success",
						Cost:       "KES 0.8000",
						MessageID:  "ATXid_abc123",
					},
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		require.NoError(t, json.NewEncoder(w).Encode(resp))
	}))
	defer mockServer.Close()

	config := conf.AfricasTalkingProviderConfiguration{
		APIKey:   "test_api_key",
		Username: "sandbox",
	}

	provider, err := NewAfricasTalkingProvider(config)
	require.NoError(t, err)

	// Override the endpoint to point to mock server
	provider.(*AfricasTalkingProvider).APIEndpoint = mockServer.URL

	t.Run("successful SMS send", func(t *testing.T) {
		messageID, err := provider.SendMessage("+254712345678", "Your OTP is: 123456", SMSProvider, "123456")
		assert.NoError(t, err)
		assert.Equal(t, "ATXid_abc123", messageID)
	})

	t.Run("rejects whatsapp channel", func(t *testing.T) {
		_, err := provider.SendMessage("+254712345678", "Your OTP is: 123456", WhatsappProvider, "123456")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "SMS channel")
	})
}

func TestAfricasTalkingProvider_SendMessage_DeliveryFailure(t *testing.T) {
	// Mock server that returns a failed delivery
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := ATResponse{
			SMSMessageData: ATSMSMessageData{
				Message: "Sent to 0/1 Total Cost: KES 0",
				Recipients: []ATRecipient{
					{
						StatusCode: 403,
						Number:     "+254000000000",
						Status:     "InvalidPhoneNumber",
						Cost:       "KES 0",
						MessageID:  "",
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		require.NoError(t, json.NewEncoder(w).Encode(resp))
	}))
	defer mockServer.Close()

	config := conf.AfricasTalkingProviderConfiguration{
		APIKey:   "test_api_key",
		Username: "sandbox",
	}

	provider, err := NewAfricasTalkingProvider(config)
	require.NoError(t, err)
	provider.(*AfricasTalkingProvider).APIEndpoint = mockServer.URL

	_, err = provider.SendMessage("+254000000000", "Your OTP is: 123456", SMSProvider, "123456")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "delivery failed")
}
