package sms_provider

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/netlify/gotrue/conf"
)

const (
	defaultSendBlueAPIBase = "https://api.sendblue.co"
)

type SendBlueProvider struct {
	Config  *conf.SendBlueProviderConfiguration
	APIPath string
}

type SendBlueResponse struct {
	Message      string `json:"message"` // this field is for auth-related errors (e.g. bad token)
	ErrorCode    int    `json:"error_code"`
	ErrorMessage string `json:"error_message"` // this field is for message-related errors (e.g. blacklisted number), https://sendblue.co/docs/outbound#error-codes
}

// Creates a SmsProvider with the SendBlue config
func NewSendBlueProvider(config conf.SendBlueProviderConfiguration) (SmsProvider, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	apiPath := defaultSendBlueAPIBase + "/api/send-message"
	return &SendBlueProvider{
		Config:  &config,
		APIPath: apiPath,
	}, nil
}

// Send an SMS containing the OTP with SendBlue's API
// See: https://sendblue.co/docs/outbound
func (t *SendBlueProvider) SendSms(phone string, message string) error {
	body, err := json.Marshal(map[string]string{
		"number":  "+" + phone, // Tests suggest SendBlue does not require a '+', but the docs have a '+'
		"content": message,
	})
	if err != nil {
		return err
	}

	client := &http.Client{Timeout: defaultTimeout}
	r, err := http.NewRequest("POST", t.APIPath, bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	r.Header.Add("Content-Type", "application/json")
	r.Header.Add("sb-api-key-id", t.Config.KeyID)
	r.Header.Add("sb-api-secret-key", t.Config.SecretKey)

	res, err := client.Do(r)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	// validate sms status
	resp := &SendBlueResponse{}
	derr := json.NewDecoder(res.Body).Decode(resp)
	if derr != nil {
		return derr
	}

	// If the `message` field is present, there was an error with the key/secret
	if resp.Message != "" {
		return fmt.Errorf("sendblue error: %v", resp.Message)
	}

	// The SendBlue API sends a null to indicate no error; this is decoded as 0
	if resp.ErrorCode != 0 {
		return fmt.Errorf("sendblue error: %v (status %v)", resp.ErrorMessage, resp.ErrorCode)
	}

	return nil
}
