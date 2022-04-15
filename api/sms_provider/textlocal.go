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
	Status string           `json:"status"`
	Errors []TextlocalError `json:"errors"`
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

// Send an SMS containing the OTP with Textlocal's API
func (t *TextlocalProvider) SendSms(phone string, message string) error {
	body := url.Values{
		"sender":  {t.Config.Sender},
		"apikey":  {t.Config.ApiKey},
		"message": {message},
		"numbers": {phone},
	}

	client := &http.Client{}
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

	resp := &TextlocalResponse{}
	derr := json.NewDecoder(res.Body).Decode(resp)
	if derr != nil {
		return derr
	}

	if len(resp.Errors) == 0 {
		return errors.New("Textlocal error: Internal Error")
	}

	if resp.Status != "success" {
		return fmt.Errorf("Textlocal error: %v (code: %v)", resp.Errors[0].Message, resp.Errors[0].Code)
	}

	return nil
}
