package sms_provider

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/supabase/gotrue/internal/conf"
	"github.com/supabase/gotrue/internal/utilities"
)

const (
	defaultPlasGateApiBase = "https://api.plasgate.com"
)

type PlasGateProvider struct {
	Config  *conf.PlasGateProviderConfiguration
	APIPath string
}

type PlasGateResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// Creates a SmsProvider with the PlasGate Config
func NewPlasGateProvider(config conf.PlasGateProviderConfiguration) (SmsProvider, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	apiPath := defaultPlasGateApiBase + "/send"
	return &PlasGateProvider{
		Config:  &config,
		APIPath: apiPath,
	}, nil
}

func (t *PlasGateProvider) SendMessage(phone string, message string, channel string) (string, error) {
	switch channel {
	case SMSProvider:
		return t.SendSms(phone, message)
	default:
		return "", fmt.Errorf("channel type %q is not supported for PlasGate", channel)
	}
}

// Send an SMS containing the OTP with PlasGate's API
func (t *PlasGateProvider) SendSms(phone string, message string) (string, error) {
	params := url.Values{
		"token":    {t.Config.Token},
		"senderID": {t.Config.SenderId},
		"phone":    {phone},
		"text":     {message},
	}

	client := &http.Client{Timeout: defaultTimeout}
	r, err := http.NewRequest("GET", t.APIPath, nil)
	r.URL.RawQuery = params.Encode()
	if err != nil {
		return "", err
	}

	r.Header.Add("Content-Type", "application/json")
	res, err := client.Do(r)
	if err != nil {
		return "", err
	}
	defer utilities.SafeClose(res.Body)

	return "", nil
}
