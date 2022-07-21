package sms_provider

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/netlify/gotrue/conf"
)

type CustomProvider struct {
	Config  *conf.CustomProviderConfiguration
}

// Creates a SmsProvider with the custom Config
func NewCustomProvider(config conf.CustomProviderConfiguration) (SmsProvider, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	return &CustomProvider{
		Config:  &config,
	}, nil
}

// Send an SMS containing the OTP with custom URL
func (t *CustomProvider) SendSms(phone string, message string) error {
	body := url.Values{
		"recipient": {phone},
		"body":      {message},
		"sender":    {t.Config.Sender},
	}

	client := &http.Client{Timeout: defaultTimeout}
	r, err := http.NewRequest("POST", t.Config.Url, strings.NewReader(body.Encode()))
	if err != nil {
		return err
	}
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	if len(t.Config.AccessToken) > 0 {
		r.Header.Add("Authorization", "Bearer "+t.Config.AccessToken)
	}
	res, err := client.Do(r)
	if err != nil {
		return err
	}

	if res.StatusCode/100 != 2 {
		return fmt.Errorf("Unexpected response while calling the SMS gateway: %v", res.StatusCode)
	}

	return nil
}
