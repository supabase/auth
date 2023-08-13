 // Africastalking documentation -  https://developers.africastalking.com/docs/sms/sending/bulk
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

type AfricastalkingRecipient struct {
	MessageID string `json:"messageId"`
	StatusCode string `json:"statusCode"`
	Status string `json:"status"`
}

type AfricastalkingSMSMessageData struct {
	Message   string             `json:"Message"`
	Recipients []AfricastalkingRecipient `json:"Recipients"`
}

type AfricastalkingResponse struct {
	SMSMessageData AfricastalkingSMSMessageData `json:"SMSMessageData"`
}

// Creates a SmsProvider with the Africastalking Config.
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

	if len(resp.SMSMessageData.Recipients) <= 0 {
		return "", errors.New("Africastalking error: Internal Error")
	}
	
	if resp.SMSMessageData.Recipients[0].Status != "Success" {
		return "", errors.New("Africastalking error: Internal Error - " + resp.SMSMessageData.Recipients[0].Status + " - " + resp.SMSMessageData.Recipients[0].StatusCode)
	}

	return resp.SMSMessageData.Recipients[0].MessageID, nil
}
