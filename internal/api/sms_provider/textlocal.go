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
	defaultTextLocalApiBase = "https://api.textlocal.in"
)

type TextlocalProvider struct {
	Config  *conf.TextlocalProviderConfiguration
	APIPath string
}

type TextlocalError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type TextlocalResponse struct {
	Status   string             `json:"status"`
	Errors   []TextlocalError   `json:"errors"`
	Messages []TextlocalMessage `json:"messages"`
}

type TextlocalMessage struct {
	MessageID string `json:"id"`
}

// Creates a SmsProvider with the Textlocal Config
func NewTextlocalProvider(config conf.TextlocalProviderConfiguration) (SmsProvider, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	apiPath := defaultTextLocalApiBase + "/send"
	return &TextlocalProvider{
		Config:  &config,
		APIPath: apiPath,
	}, nil
}

func (t *TextlocalProvider) SendMessage(phone string, message string, channel string) (string, error) {
	switch channel {
	case SMSProvider:
		return t.SendSms(phone, message)
	default:
		return "", fmt.Errorf("channel type %q is not supported for TextLocal", channel)
	}
}

// Send an SMS containing the OTP with Textlocal's API
func (t *TextlocalProvider) SendSms(phone string, message string) (string, error) {
	body := url.Values{
		"sender":  {t.Config.Sender},
		"apikey":  {t.Config.ApiKey},
		"message": {message},
		"numbers": {phone},
	}

	client := &http.Client{Timeout: defaultTimeout}
	r, err := http.NewRequest("POST", t.APIPath, strings.NewReader(body.Encode()))
	if err != nil {
		return "", err
	}

	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	res, err := client.Do(r)
	if err != nil {
		return "", err
	}
	defer utilities.SafeClose(res.Body)

	resp := &TextlocalResponse{}
	derr := json.NewDecoder(res.Body).Decode(resp)
	if derr != nil {
		return "", derr
	}

	if len(resp.Errors) > 0 {
		return "", errors.New("textlocal error: Internal Error")
	}

	messageID := ""

	if resp.Status != "success" {
		if len(resp.Messages) > 0 {
			messageID = resp.Messages[0].MessageID
		}

		return messageID, fmt.Errorf("textlocal error: %v (code: %v) message %s", resp.Errors[0].Message, resp.Errors[0].Code, messageID)
	}

	return messageID, nil
}
