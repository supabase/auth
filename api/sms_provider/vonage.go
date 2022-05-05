package sms_provider

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/netlify/gotrue/conf"
)

const (
	defaultVonageApiBase = "https://rest.nexmo.com"
)

type VonageProvider struct {
	Config  *conf.VonageProviderConfiguration
	APIPath string
}

type VonageResponseMessage struct {
	Status    string `json:"status"`
	ErrorText string `json:"error-text"`
}

type VonageResponse struct {
	Messages []VonageResponseMessage `json:"messages"`
}

// Creates a SmsProvider with the Vonage Config
func NewVonageProvider(config conf.VonageProviderConfiguration) (SmsProvider, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	apiPath := defaultVonageApiBase + "/sms/json"
	return &VonageProvider{
		Config:  &config,
		APIPath: apiPath,
	}, nil
}

// Send an SMS containing the OTP with Vonage's API
func (t *VonageProvider) SendSms(phone string, message string) error {
	body := url.Values{
		"from":       {t.Config.From},
		"to":         {phone},
		"text":       {message},
		"api_key":    {t.Config.ApiKey},
		"api_secret": {t.Config.ApiSecret},
	}

	client := &http.Client{Timeout: defaultTimeout}
	r, err := http.NewRequest("POST", t.APIPath, strings.NewReader(body.Encode()))
	if err != nil {
		return err
	}

	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	res, err := client.Do(r)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	resp := &VonageResponse{}
	derr := json.NewDecoder(res.Body).Decode(resp)
	if derr != nil {
		return derr
	}

	if len(resp.Messages) <= 0 {
		return errors.New("Vonage error: Internal Error")
	}

	// A status of zero indicates success; a non-zero value means something went wrong.
	if resp.Messages[0].Status != "0" {
		return fmt.Errorf("Vonage error: %v (status: %v)", resp.Messages[0].ErrorText, resp.Messages[0].Status)
	}

	return nil
}
