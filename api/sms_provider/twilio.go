package sms_provider

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/netlify/gotrue/conf"
)

const (
	defaultTwilioApiBase = "https://api.twilio.com"
	apiVersion           = "2010-04-01"
)

type TwilioProvider struct {
	Config  *conf.TwilioProviderConfiguration
	APIPath string
}

type SmsStatus struct {
	To           string `json:"to"`
	From         string `json:"from"`
	Status       string `json:"status"`
	ErrorCode    string `json:"error_code"`
	ErrorMessage string `json:"error_message"`
	Body         string `json:"body"`
}

type twilioErrResponse struct {
	Code     int    `json:"code"`
	Message  string `json:"message"`
	MoreInfo string `json:"more_info"`
	Status   int    `json:"status"`
}

func (t twilioErrResponse) Error() string {
	return fmt.Sprintf("%s More information: %s", t.Message, t.MoreInfo)
}

// Creates a SmsProvider with the Twilio Config
func NewTwilioProvider(config conf.TwilioProviderConfiguration) (SmsProvider, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	apiPath := defaultTwilioApiBase + "/" + apiVersion + "/" + "Accounts" + "/" + config.AccountSid + "/Messages.json"
	return &TwilioProvider{
		Config:  &config,
		APIPath: apiPath,
	}, nil
}

// Send an SMS containing the OTP with Twilio's API
func (t *TwilioProvider) SendSms(phone string, message string) error {
	body := url.Values{
		"To":      {"+" + phone}, // twilio api requires "+" extension to be included
		"Channel": {"sms"},
		"From":    {t.Config.MessageServiceSid},
		"Body":    {message},
	}

	client := &http.Client{Timeout: defaultTimeout}
	r, err := http.NewRequest("POST", t.APIPath, strings.NewReader(body.Encode()))
	if err != nil {
		return err
	}
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth(t.Config.AccountSid, t.Config.AuthToken)
	res, err := client.Do(r)
	if err != nil {
		return err
	}
	if res.StatusCode/100 != 2 {
		resp := &twilioErrResponse{}
		if err := json.NewDecoder(res.Body).Decode(resp); err != nil {
			return err
		}
		return resp
	}
	defer res.Body.Close()

	// validate sms status
	resp := &SmsStatus{}
	derr := json.NewDecoder(res.Body).Decode(resp)
	if derr != nil {
		return derr
	}

	if resp.Status == "failed" || resp.Status == "undelivered" {
		return fmt.Errorf("Twilio error: %v %v", resp.ErrorMessage, resp.ErrorCode)
	}

	return nil
}
