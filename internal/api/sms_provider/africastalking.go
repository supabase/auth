package sms_provider

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/supabase/gotrue/internal/conf"
	"github.com/supabase/gotrue/internal/utilities"
)

const (
	defaultAfricastalkingApiBase = "https://api.africastalking.com/version1/messaging"
)

type AfricastalkingProvider struct {
	Config  *conf.AfricastalkingProviderConfiguration
	APIPath string
}

type AfricastalkingError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type AfricastalkingResponse struct {
	Status   string             `json:"status"`
	Errors   []AfricastalkingError   `json:"errors"`
	Messages []AfricastalkingMessage `json:"messages"`
}

type AfricastalkingMessage struct {
	MessageID string `json:"id"`
}

// Creates a SmsProvider with the Africastalking Config
func NewAfricastalkingProvider(config conf.AfricastalkingProviderConfiguration) (SmsProvider, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	apiPath := defaultAfricastalkingApiBase
	return &AfricastalkingProvider{
		Config:  &config,
		APIPath: apiPath,
	}, nil
}

func (t *AfricastalkingProvider) SendMessage(phone string, message string, channel string) (string, error) {
	switch channel {
	case SMSProvider:
		return t.SendSms(phone, message)
	default:
		return "", fmt.Errorf("channel type %q is not supported for Africastalking", channel)
	}
}

// Send an SMS containing the OTP with Africastalking's API
func (t *AfricastalkingProvider) SendSms(phone string, message string) (string, error) {
	body := url.Values{
		"username": {t.Config.Username},
		"message": {message},
		"to": {phone},
	}

	if t.Config.From != "" {
		body.Add("from", t.Config.From)
	}

	client := &http.Client{Timeout: defaultTimeout}
	r, err := http.NewRequest("POST", t.APIPath, strings.NewReader(body.Encode()))
	if err != nil {
		return "", err
	}

	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Add("Accept", "application/json")
	r.Header.Add("apiKey", t.Config.ApiKey)
	res, err := client.Do(r)
	if err != nil {
		return "", err
	}
	defer utilities.SafeClose(res.Body)

	resp := &AfricastalkingResponse{}
	derr := json.NewDecoder(res.Body).Decode(resp)
	if derr != nil {
		return "", derr
	}

	if len(resp.Errors) > 0 {
		return "", errors.New("Africastalking error: Internal Error")
	}

	messageID := ""

	if resp.Status != "success" {
		if len(resp.Messages) > 0 {
			messageID = resp.Messages[0].MessageID
		}

		return messageID, fmt.Errorf("Africastalking error: %v (code: %v) message %s", resp.Errors[0].Message, resp.Errors[0].Code, messageID)
	}

	return messageID, nil
}
