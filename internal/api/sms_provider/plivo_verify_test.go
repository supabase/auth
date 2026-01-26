package sms_provider

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
)

func TestPlivoVerifyProviderConfiguration_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  conf.PlivoVerifyProviderConfiguration
		wantErr string
	}{
		{
			name: "valid config",
			config: conf.PlivoVerifyProviderConfiguration{
				AuthID:    "test_auth_id",
				AuthToken: "test_auth_token",
				AppUUID:   "test_app_uuid",
			},
			wantErr: "",
		},
		{
			name: "valid config with optional fields",
			config: conf.PlivoVerifyProviderConfiguration{
				AuthID:     "test_auth_id",
				AuthToken:  "test_auth_token",
				AppUUID:    "test_app_uuid",
				Locale:     "en_US",
				BrandName:  "TestApp",
				CodeLength: 6,
			},
			wantErr: "",
		},
		{
			name: "missing auth_id",
			config: conf.PlivoVerifyProviderConfiguration{
				AuthToken: "test_auth_token",
				AppUUID:   "test_app_uuid",
			},
			wantErr: "missing auth_id",
		},
		{
			name: "missing auth_token",
			config: conf.PlivoVerifyProviderConfiguration{
				AuthID:  "test_auth_id",
				AppUUID: "test_app_uuid",
			},
			wantErr: "missing auth_token",
		},
		{
			name: "missing app_uuid",
			config: conf.PlivoVerifyProviderConfiguration{
				AuthID:    "test_auth_id",
				AuthToken: "test_auth_token",
			},
			wantErr: "missing app_uuid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

func TestNewPlivoVerifyProvider(t *testing.T) {
	t.Run("valid config creates provider", func(t *testing.T) {
		config := conf.PlivoVerifyProviderConfiguration{
			AuthID:    "test_auth_id",
			AuthToken: "test_auth_token",
			AppUUID:   "test_app_uuid",
		}

		provider, err := NewPlivoVerifyProvider(config)
		require.NoError(t, err)
		assert.NotNil(t, provider)
	})

	t.Run("invalid config returns error", func(t *testing.T) {
		config := conf.PlivoVerifyProviderConfiguration{
			AuthID: "test_auth_id",
			// Missing AuthToken and AppUUID
		}

		provider, err := NewPlivoVerifyProvider(config)
		assert.Error(t, err)
		assert.Nil(t, provider)
	})
}

func TestPlivoVerifyProvider_SendMessage(t *testing.T) {
	t.Run("successful SMS session creation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Contains(t, r.URL.Path, "/Verify/Session/")
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

			username, password, ok := r.BasicAuth()
			assert.True(t, ok)
			assert.Equal(t, "test_auth_id", username)
			assert.Equal(t, "test_auth_token", password)

			var reqBody plivoCreateSessionRequest
			err := json.NewDecoder(r.Body).Decode(&reqBody)
			require.NoError(t, err)
			assert.Equal(t, "+14155551234", reqBody.Recipient)
			assert.Equal(t, "sms", reqBody.Channel)
			assert.Equal(t, "test_app_uuid", reqBody.AppUUID)

			resp := PlivoVerifySessionResponse{
				ApiID:       "test_api_id",
				Message:     "Session initiated",
				SessionUUID: "test_session_uuid_123",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		provider := createPlivoVerifyTestProvider(t, server.URL)
		sessionUUID, err := provider.SendMessage("+14155551234", "ignored", SMSProvider, "ignored")

		require.NoError(t, err)
		assert.Equal(t, "test_session_uuid_123", sessionUUID)
	})

	t.Run("successful voice session creation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var reqBody plivoCreateSessionRequest
			err := json.NewDecoder(r.Body).Decode(&reqBody)
			require.NoError(t, err)
			assert.Equal(t, "voice", reqBody.Channel)

			resp := PlivoVerifySessionResponse{
				ApiID:       "test_api_id",
				Message:     "Session initiated",
				SessionUUID: "voice_session_uuid",
			}
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		provider := createPlivoVerifyTestProvider(t, server.URL)
		sessionUUID, err := provider.SendMessage("+14155551234", "ignored", VoiceChannel, "ignored")

		require.NoError(t, err)
		assert.Equal(t, "voice_session_uuid", sessionUUID)
	})

	t.Run("handles API error response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			resp := PlivoVerifyErrorResponse{
				ApiID:   "test_api_id",
				Error:   "invalid_phone",
				Message: "The phone number format is invalid",
			}
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		provider := createPlivoVerifyTestProvider(t, server.URL)
		_, err := provider.SendMessage("invalid", "msg", SMSProvider, "123")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_phone")
	})

	t.Run("rejects unsupported channel", func(t *testing.T) {
		provider := createPlivoVerifyTestProvider(t, "http://localhost")
		_, err := provider.SendMessage("+14155551234", "msg", "whatsapp", "123456")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported channel")
	})
}

func TestPlivoVerifyProvider_VerifyOTP(t *testing.T) {
	t.Run("successful OTP verification", func(t *testing.T) {
		callCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount++
			if callCount == 1 {
				resp := PlivoVerifySessionResponse{
					ApiID:       "test_api_id",
					Message:     "Session initiated",
					SessionUUID: "verify_session_uuid",
				}
				json.NewEncoder(w).Encode(resp)
				return
			}

			assert.Contains(t, r.URL.Path, "/Verify/Session/verify_session_uuid/")

			var reqBody plivoValidateSessionRequest
			err := json.NewDecoder(r.Body).Decode(&reqBody)
			require.NoError(t, err)
			assert.Equal(t, "123456", reqBody.OTP)

			resp := PlivoVerifyValidationResponse{
				ApiID:   "test_api_id",
				Message: "session validated successfully.",
			}
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		provider := createPlivoVerifyTestProvider(t, server.URL)

		_, err := provider.SendMessage("+14155551234", "msg", SMSProvider, "otp")
		require.NoError(t, err)

		err = provider.VerifyOTP("+14155551234", "123456")
		assert.NoError(t, err)
	})

	t.Run("verification fails with invalid OTP", func(t *testing.T) {
		callCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount++
			if callCount == 1 {
				resp := PlivoVerifySessionResponse{
					ApiID:       "test_api_id",
					Message:     "Session initiated",
					SessionUUID: "verify_session_uuid",
				}
				json.NewEncoder(w).Encode(resp)
				return
			}

			w.WriteHeader(http.StatusBadRequest)
			resp := PlivoVerifyErrorResponse{
				ApiID:   "test_api_id",
				Error:   "invalid_otp",
				Message: "The OTP is incorrect",
			}
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		provider := createPlivoVerifyTestProvider(t, server.URL)

		_, err := provider.SendMessage("+14155551234", "msg", SMSProvider, "otp")
		require.NoError(t, err)

		err = provider.VerifyOTP("+14155551234", "wrong_otp")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_otp")
	})

	t.Run("verification fails with no active session", func(t *testing.T) {
		provider := createPlivoVerifyTestProvider(t, "http://localhost")
		err := provider.VerifyOTP("+14155551234", "123456")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no active session")
	})
}

func TestPlivoVerifyProvider_SessionCache(t *testing.T) {
	t.Run("session expires after TTL", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := PlivoVerifySessionResponse{
				ApiID:       "test_api_id",
				Message:     "Session initiated",
				SessionUUID: "expiring_session_uuid",
			}
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		provider := createPlivoVerifyTestProvider(t, server.URL)
		plivoProvider := provider.(*PlivoVerifyProvider)
		plivoProvider.sessionTTL = 50 * time.Millisecond

		_, err := provider.SendMessage("+14155551234", "msg", SMSProvider, "otp")
		require.NoError(t, err)

		// Session should be cached
		_, ok := plivoProvider.getSession("+14155551234")
		assert.True(t, ok)

		// Wait for expiration
		time.Sleep(100 * time.Millisecond)

		// Session should be expired
		_, ok = plivoProvider.getSession("+14155551234")
		assert.False(t, ok)
	})
}

func TestPlivoVerifyProvider_OptionalParameters(t *testing.T) {
	t.Run("sends optional parameters when configured", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var reqBody plivoCreateSessionRequest
			err := json.NewDecoder(r.Body).Decode(&reqBody)
			require.NoError(t, err)

			assert.Equal(t, "en_US", reqBody.Locale)
			assert.Equal(t, "TestBrand", reqBody.BrandName)
			assert.Equal(t, 8, reqBody.CodeLength)

			resp := PlivoVerifySessionResponse{
				ApiID:       "test_api_id",
				Message:     "Session initiated",
				SessionUUID: "optional_params_session",
			}
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		config := conf.PlivoVerifyProviderConfiguration{
			AuthID:     "test_auth_id",
			AuthToken:  "test_auth_token",
			AppUUID:    "test_app_uuid",
			Locale:     "en_US",
			BrandName:  "TestBrand",
			CodeLength: 8,
		}

		provider, err := NewPlivoVerifyProvider(config)
		require.NoError(t, err)
		plivoProvider := provider.(*PlivoVerifyProvider)
		plivoProvider.APIBasePath = server.URL

		_, err = provider.SendMessage("+14155551234", "msg", SMSProvider, "otp")
		assert.NoError(t, err)
	})
}

// Helper function to create a test provider with custom API base
func createPlivoVerifyTestProvider(t *testing.T, apiBase string) SmsProvider {
	config := conf.PlivoVerifyProviderConfiguration{
		AuthID:    "test_auth_id",
		AuthToken: "test_auth_token",
		AppUUID:   "test_app_uuid",
	}

	provider, err := NewPlivoVerifyProvider(config)
	require.NoError(t, err)

	plivoProvider := provider.(*PlivoVerifyProvider)
	plivoProvider.APIBasePath = strings.TrimSuffix(apiBase, "/")

	return provider
}
