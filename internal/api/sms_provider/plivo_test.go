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

func TestNewPlivoProvider(t *testing.T) {
	t.Run("valid configuration", func(t *testing.T) {
		config := conf.PlivoProviderConfiguration{
			AuthID:    "test_auth_id",
			AuthToken: "test_auth_token",
			SenderID:  "+14155551234",
		}

		provider, err := NewPlivoProvider(config)

		assert.NoError(t, err)
		assert.NotNil(t, provider)
		plivoProvider := provider.(*PlivoProvider)
		assert.Equal(t, "test_auth_id", plivoProvider.Config.AuthID)
		assert.Equal(t, "test_auth_token", plivoProvider.Config.AuthToken)
		assert.Equal(t, "+14155551234", plivoProvider.Config.SenderID)
		assert.Contains(t, plivoProvider.APIPath, "test_auth_id")
	})

	t.Run("missing auth id", func(t *testing.T) {
		config := conf.PlivoProviderConfiguration{
			AuthToken: "test_auth_token",
			SenderID:  "+14155551234",
		}

		provider, err := NewPlivoProvider(config)

		assert.Error(t, err)
		assert.Nil(t, provider)
		assert.Contains(t, err.Error(), "Auth ID")
	})

	t.Run("missing auth token", func(t *testing.T) {
		config := conf.PlivoProviderConfiguration{
			AuthID:   "test_auth_id",
			SenderID: "+14155551234",
		}

		provider, err := NewPlivoProvider(config)

		assert.Error(t, err)
		assert.Nil(t, provider)
		assert.Contains(t, err.Error(), "Auth Token")
	})

	t.Run("missing sender id", func(t *testing.T) {
		config := conf.PlivoProviderConfiguration{
			AuthID:    "test_auth_id",
			AuthToken: "test_auth_token",
		}

		provider, err := NewPlivoProvider(config)

		assert.Error(t, err)
		assert.Nil(t, provider)
		assert.Contains(t, err.Error(), "Sender ID")
	})

	t.Run("empty configuration", func(t *testing.T) {
		config := conf.PlivoProviderConfiguration{}

		provider, err := NewPlivoProvider(config)

		assert.Error(t, err)
		assert.Nil(t, provider)
	})
}

func TestPlivoProvider_SendMessage(t *testing.T) {
	t.Run("SMS channel supported", func(t *testing.T) {
		// Create mock server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify request method
			assert.Equal(t, "POST", r.Method)

			// Verify authorization header exists
			assert.NotEmpty(t, r.Header.Get("Authorization"))
			assert.Contains(t, r.Header.Get("Authorization"), "Basic")

			// Verify content type
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

			// Return success response
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(PlivoResponse{
				MessageUUID: []string{"test-uuid-12345"},
				Message:     "message(s) queued",
				ApiID:       "test-api-id",
			})
		}))
		defer server.Close()

		config := conf.PlivoProviderConfiguration{
			AuthID:    "test_auth_id",
			AuthToken: "test_auth_token",
			SenderID:  "+14155551234",
		}

		provider, err := NewPlivoProvider(config)
		require.NoError(t, err)

		// Override API path to use mock server
		plivoProvider := provider.(*PlivoProvider)
		plivoProvider.APIPath = server.URL

		messageID, err := provider.SendMessage("+15551234567", "Test message", SMSProvider, "123456")

		assert.NoError(t, err)
		assert.Equal(t, "test-uuid-12345", messageID)
	})

	t.Run("WhatsApp channel supported", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)

			// Verify WhatsApp type is set
			assert.Equal(t, "whatsapp", body["type"])
			assert.Equal(t, "+14155551234", body["src"])
			assert.Equal(t, "15551234567", body["dst"])

			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(PlivoResponse{
				MessageUUID: []string{"whatsapp-uuid-12345"},
				Message:     "message(s) queued",
			})
		}))
		defer server.Close()

		config := conf.PlivoProviderConfiguration{
			AuthID:    "test_auth_id",
			AuthToken: "test_auth_token",
			SenderID:  "+14155551234",
		}

		provider, err := NewPlivoProvider(config)
		require.NoError(t, err)

		plivoProvider := provider.(*PlivoProvider)
		plivoProvider.APIPath = server.URL

		messageID, err := provider.SendMessage("+15551234567", "Test message", WhatsappProvider, "123456")

		assert.NoError(t, err)
		assert.Equal(t, "whatsapp-uuid-12345", messageID)
	})

	t.Run("unsupported channel", func(t *testing.T) {
		config := conf.PlivoProviderConfiguration{
			AuthID:    "test_auth_id",
			AuthToken: "test_auth_token",
			SenderID:  "+14155551234",
		}

		provider, err := NewPlivoProvider(config)
		require.NoError(t, err)

		_, err = provider.SendMessage("+15551234567", "Test message", "unsupported_channel", "123456")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not supported")
	})
}

func TestPlivoProvider_SendSms(t *testing.T) {
	t.Run("successful SMS send", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify request body
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)

			assert.Equal(t, "+14155551234", body["src"])
			assert.Equal(t, "15551234567", body["dst"]) // + should be stripped
			assert.Equal(t, "Your code is 123456", body["text"])
			assert.Empty(t, body["type"]) // SMS should not have type field

			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(PlivoResponse{
				MessageUUID: []string{"msg-uuid-001"},
				Message:     "message(s) queued",
			})
		}))
		defer server.Close()

		config := conf.PlivoProviderConfiguration{
			AuthID:    "test_auth_id",
			AuthToken: "test_auth_token",
			SenderID:  "+14155551234",
		}

		provider, _ := NewPlivoProvider(config)
		provider.(*PlivoProvider).APIPath = server.URL

		messageID, err := provider.(*PlivoProvider).SendSms("+15551234567", "Your code is 123456", SMSProvider)

		assert.NoError(t, err)
		assert.Equal(t, "msg-uuid-001", messageID)
	})

	t.Run("successful WhatsApp send", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)

			assert.Equal(t, "whatsapp", body["type"]) // WhatsApp should have type field
			assert.Equal(t, "+14155551234", body["src"])
			assert.Equal(t, "15551234567", body["dst"])

			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(PlivoResponse{
				MessageUUID: []string{"whatsapp-uuid-001"},
				Message:     "message(s) queued",
			})
		}))
		defer server.Close()

		config := conf.PlivoProviderConfiguration{
			AuthID:    "test_auth_id",
			AuthToken: "test_auth_token",
			SenderID:  "+14155551234",
		}

		provider, _ := NewPlivoProvider(config)
		provider.(*PlivoProvider).APIPath = server.URL

		messageID, err := provider.(*PlivoProvider).SendSms("+15551234567", "Your code is 123456", WhatsappProvider)

		assert.NoError(t, err)
		assert.Equal(t, "whatsapp-uuid-001", messageID)
	})

	t.Run("phone number without plus prefix", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)

			// Should not have double processing
			assert.Equal(t, "15551234567", body["dst"])

			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(PlivoResponse{
				MessageUUID: []string{"msg-uuid-002"},
			})
		}))
		defer server.Close()

		config := conf.PlivoProviderConfiguration{
			AuthID:    "test_auth_id",
			AuthToken: "test_auth_token",
			SenderID:  "+14155551234",
		}

		provider, _ := NewPlivoProvider(config)
		provider.(*PlivoProvider).APIPath = server.URL

		messageID, err := provider.(*PlivoProvider).SendSms("15551234567", "Test", SMSProvider)

		assert.NoError(t, err)
		assert.Equal(t, "msg-uuid-002", messageID)
	})

	t.Run("API error response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(PlivoErrorResponse{
				Error: "invalid destination number",
			})
		}))
		defer server.Close()

		config := conf.PlivoProviderConfiguration{
			AuthID:    "test_auth_id",
			AuthToken: "test_auth_token",
			SenderID:  "+14155551234",
		}

		provider, _ := NewPlivoProvider(config)
		provider.(*PlivoProvider).APIPath = server.URL

		_, err := provider.(*PlivoProvider).SendSms("+15551234567", "Test", SMSProvider)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid destination number")
	})

	t.Run("authentication error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(PlivoErrorResponse{
				Error: "authentication failed",
			})
		}))
		defer server.Close()

		config := conf.PlivoProviderConfiguration{
			AuthID:    "invalid_id",
			AuthToken: "invalid_token",
			SenderID:  "+14155551234",
		}

		provider, _ := NewPlivoProvider(config)
		provider.(*PlivoProvider).APIPath = server.URL

		_, err := provider.(*PlivoProvider).SendSms("+15551234567", "Test", SMSProvider)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "authentication failed")
	})

	t.Run("server error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		config := conf.PlivoProviderConfiguration{
			AuthID:    "test_auth_id",
			AuthToken: "test_auth_token",
			SenderID:  "+14155551234",
		}

		provider, _ := NewPlivoProvider(config)
		provider.(*PlivoProvider).APIPath = server.URL

		_, err := provider.(*PlivoProvider).SendSms("+15551234567", "Test", SMSProvider)

		assert.Error(t, err)
	})
}

func TestPlivoProvider_VerifyOTP(t *testing.T) {
	t.Run("returns error - not supported", func(t *testing.T) {
		config := conf.PlivoProviderConfiguration{
			AuthID:    "test_auth_id",
			AuthToken: "test_auth_token",
			SenderID:  "+14155551234",
		}

		provider, _ := NewPlivoProvider(config)

		err := provider.VerifyOTP("+15551234567", "123456")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not supported")
	})
}
