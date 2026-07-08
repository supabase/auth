package sms_provider

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/utilities"
)

// Africa's Talking API endpoints
const (
	ATProductionEndpoint = "https://api.africastalking.com/version1/messaging"
	ATSandboxEndpoint    = "https://api.sandbox.africastalking.com/version1/messaging"
)

// AfricasTalkingProvider implements the SmsProvider interface for Africa's Talking
type AfricasTalkingProvider struct {
	Config      *conf.AfricasTalkingProviderConfiguration
	APIEndpoint string
}

// ATRecipient represents a single recipient in the AT API response
type ATRecipient struct {
	StatusCode int    `json:"statusCode"`
	Number     string `json:"number"`
	Status     string `json:"status"`
	Cost       string `json:"cost"`
	MessageID  string `json:"messageId"`
}

// ATSMSMessageData holds the message data from the AT API response
type ATSMSMessageData struct {
	Message    string        `json:"Message"`
	Recipients []ATRecipient `json:"Recipients"`
}

// ATResponse is the top-level response from Africa's Talking SMS API
type ATResponse struct {
	SMSMessageData ATSMSMessageData `json:"SMSMessageData"`
}

// NewAfricasTalkingProvider creates and returns a new AfricasTalkingProvider
func NewAfricasTalkingProvider(config conf.AfricasTalkingProviderConfiguration) (SmsProvider, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	endpoint := ATProductionEndpoint
	if config.Username == "sandbox" {
		endpoint = ATSandboxEndpoint
	}

	return &AfricasTalkingProvider{
		Config:      &config,
		APIEndpoint: endpoint,
	}, nil
}

// SendMessage sends an OTP SMS via Africa's Talking API and returns the message ID
func (a *AfricasTalkingProvider) SendMessage(phone, message, channel, otp string) (string, error) {
	switch channel {
	case SMSProvider:
		return a.SendSms(phone, message)
	default:
		return "", fmt.Errorf("africas_talking: channel type %q is not supported, only the SMS channel is available", channel)
	}
}

// SendSms sends an SMS containing the OTP via the Africa's Talking API
func (a *AfricasTalkingProvider) SendSms(phone, message string) (string, error) {
	params := url.Values{}
	params.Set("username", a.Config.Username)
	params.Set("to", phone)
	params.Set("message", message)

	// Sender ID is optional — if blank, AT uses a shared shortcode
	if a.Config.SenderID != "" {
		params.Set("from", a.Config.SenderID)
	}

	client := &http.Client{Timeout: defaultTimeout}
	req, err := http.NewRequest(http.MethodPost, a.APIEndpoint, strings.NewReader(params.Encode()))
	if err != nil {
		return "", fmt.Errorf("africas_talking: failed to create request: %w", err)
	}

	req.Header.Set("apiKey", a.Config.APIKey)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("africas_talking: request failed: %w", err)
	}
	defer utilities.SafeClose(resp.Body)

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("africas_talking: unexpected HTTP status: %d", resp.StatusCode)
	}

	var atResp ATResponse
	if err := json.NewDecoder(resp.Body).Decode(&atResp); err != nil {
		return "", fmt.Errorf("africas_talking: failed to decode response: %w", err)
	}

	recipients := atResp.SMSMessageData.Recipients
	if len(recipients) == 0 {
		return "", fmt.Errorf("africas_talking: no recipients in response: %s", atResp.SMSMessageData.Message)
	}

	recipient := recipients[0]

	// statusCode 101 = success on Africa's Talking
	if recipient.StatusCode != 101 {
		return recipient.MessageID, fmt.Errorf(
			"africas_talking: delivery failed for %s — status: %s (code: %d)",
			recipient.Number,
			recipient.Status,
			recipient.StatusCode,
		)
	}

	return recipient.MessageID, nil
}

// VerifyOTP is not supported by Africa's Talking; OTPs are verified internally.
func (a *AfricasTalkingProvider) VerifyOTP(phone, code string) error {
	return fmt.Errorf("VerifyOTP is not supported for Africa's Talking")
}
