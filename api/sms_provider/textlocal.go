package sms_provider

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/netlify/gotrue/conf"
)

const (
	defaultTextLocalApiBase = "https://api.textlocal.in"
)

type TextLocalProvider struct {
	Config  *conf.TextLocalProviderConfiguration
	APIPath string
}

type TextLocalResponse struct {
	Status int `json:"status"`
}

type TextLocalError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type TextLocalErrResponse struct {
	Errors []TextLocalError `json:"errors"`
}

func (t TextLocalErrResponse) Error() string {
	return t.Errors[0].Message
}

// Creates a SmsProvider with the TextLocal Config
func NewTextLocalProvider(config conf.TextLocalProviderConfiguration) (SmsProvider, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	apiPath := defaultTextLocalApiBase + "/send/?"
	return &TextLocalProvider{
		Config:  &config,
		APIPath: apiPath,
	}, nil
}

// Send an SMS containing the OTP with TextLocal's API
func (t TextLocalProvider) SendSms(phone string, message string) error {
	params := url.Values{
		"apikey":  {t.Config.ApiKey},
		"sender":  {t.Config.Sender},
		"message": {message},
		"numbers": {phone},
	}

	client := &http.Client{}
	r, err := http.NewRequest("GET", t.APIPath+params.Encode(), nil)
	if err != nil {
		return err
	}

	res, err := client.Do(r)
	if err != nil {
		return err
	}

	if res.StatusCode == http.StatusBadRequest || res.StatusCode == http.StatusForbidden || res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusUnprocessableEntity {
		resp := &TextLocalErrResponse{}
		if err := json.NewDecoder(res.Body).Decode(resp); err != nil {
			return err
		}
		return resp
	}
	defer res.Body.Close()

	// validate sms status
	resp := &TextLocalResponse{}
	derr := json.NewDecoder(res.Body).Decode(resp)
	if derr != nil {
		return derr
	}

	if resp.Status != 200 {
		return fmt.Errorf("TextLocal error: error in sending status.")
	}

	return nil
}
