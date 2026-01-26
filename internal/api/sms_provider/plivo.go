package sms_provider

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/utilities"
)

const (
	defaultPlivoAPIBase = "https://api.plivo.com/v1/Account/"
)

// PlivoProvider implements the SmsProvider interface for Plivo's Messaging API
type PlivoProvider struct {
	Config  *conf.PlivoProviderConfiguration
	APIPath string
}

// PlivoResponse represents the response from Plivo's Messaging API
type PlivoResponse struct {
	MessageUUID []string `json:"message_uuid"`
	Message     string   `json:"message"`
	ApiID       string   `json:"api_id"`
	Error       string   `json:"error"`
}

// PlivoErrorResponse represents an error response from Plivo API
type PlivoErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	ApiID   string `json:"api_id"`
}

// NewPlivoProvider creates and validates a new Plivo provider instance
func NewPlivoProvider(config conf.PlivoProviderConfiguration) (SmsProvider, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	apiPath := defaultPlivoAPIBase + config.AuthID + "/Message/"

	return &PlivoProvider{
		Config:  &config,
		APIPath: apiPath,
	}, nil
}

// SendMessage implements the SmsProvider interface
func (p *PlivoProvider) SendMessage(phone, message, channel, otp string) (string, error) {
	switch channel {
	case SMSProvider, WhatsappProvider:
		return p.SendSms(phone, message, channel)
	default:
		return "", fmt.Errorf("channel %s is not supported for Plivo", channel)
	}
}

// SendSms sends a message via the Plivo API (supports both SMS and WhatsApp)
func (p *PlivoProvider) SendSms(phone, message, channel string) (string, error) {
	// Plivo expects phone numbers without the + prefix
	phone = strings.TrimPrefix(phone, "+")

	// Build request body
	body := map[string]string{
		"src":  p.Config.SenderID,
		"dst":  phone,
		"text": message,
	}

	// Add type parameter for WhatsApp messages
	if channel == WhatsappProvider {
		body["type"] = "whatsapp"
	}

	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("plivo: failed to marshal request body: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", p.APIPath, strings.NewReader(string(bodyJSON)))
	if err != nil {
		return "", fmt.Errorf("plivo: failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(p.Config.AuthID, p.Config.AuthToken)

	// Send request
	client := &http.Client{Timeout: defaultTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("plivo: failed to send request: %w", err)
	}
	defer utilities.SafeClose(resp.Body)

	// Handle error responses
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusCreated {
		var errResp PlivoErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
			return "", fmt.Errorf("plivo: request failed with status %d", resp.StatusCode)
		}
		return "", fmt.Errorf("plivo: %s", errResp.Error)
	}

	// Parse success response
	var plivoResp PlivoResponse
	if err := json.NewDecoder(resp.Body).Decode(&plivoResp); err != nil {
		return "", fmt.Errorf("plivo: failed to parse response: %w", err)
	}

	// Return message UUID
	if len(plivoResp.MessageUUID) > 0 {
		return plivoResp.MessageUUID[0], nil
	}

	return "", nil
}

// VerifyOTP is not supported by Plivo's basic SMS API
func (p *PlivoProvider) VerifyOTP(phone, token string) error {
	return fmt.Errorf("VerifyOTP is not supported for Plivo")
}
