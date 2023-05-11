package sms_provider

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/supabase/gotrue/internal/conf"
	"github.com/supabase/gotrue/internal/utilities"
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

func (t *TwilioProvider) SendMessage(phone string, message string, channel string) error {
	switch channel {
	case SMSProvider, WhatsappProvider:
		return t.SendSms(phone, message, channel)
	default:
		return fmt.Errorf("channel type %q is not supported for Twilio", channel)
	}
}

// Send an SMS containing the OTP with Twilio's API
func (t *TwilioProvider) SendSms(phone, message, channel string) error {
	sender := t.Config.MessageServiceSid
	receiver := "+" + phone
	if channel == WhatsappProvider {
		receiver = channel + ":" + receiver
		sender = channel + ":" + sender
	}
	body := url.Values{
		"To":      {receiver}, // twilio api requires "+" extension to be included
		"Channel": {channel},
		"From":    {sender},
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
	defer utilities.SafeClose(res.Body)
	if err != nil {
		return err
	}
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusCreated {
		resp := &twilioErrResponse{}
		if err := json.NewDecoder(res.Body).Decode(resp); err != nil {
			return err
		}
		return resp
	}
	// validate sms status
	resp := &SmsStatus{}
	derr := json.NewDecoder(res.Body).Decode(resp)
	if derr != nil {
		return derr
	}

	if resp.Status == "failed" || resp.Status == "undelivered" {
		return fmt.Errorf("twilio error: %v %v", resp.ErrorMessage, resp.ErrorCode)
	}

	return nil
}
