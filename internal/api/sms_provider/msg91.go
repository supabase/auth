package sms_provider

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/supabase/gotrue/internal/conf"
	"github.com/supabase/gotrue/internal/utilities"
)

const (
	defaultMsg91ApiBase = "https://api.msg91.com/api/sendhttp.php"
)

type Msg91Provider struct {
	Config  *conf.Msg91ProviderConfiguration
	APIPath string
}

type Msg91Response struct {
	Message string `json:"message"`
	Type    string `json:"type"`
}

// NewMsg91Provider creates a new SmsProvider for Msg91.
func NewMsg91Provider(config conf.Msg91ProviderConfiguration) (SmsProvider, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	return &Msg91Provider{
		Config:  &config,
		APIPath: defaultMsg91ApiBase,
	}, nil
}

func (t *Msg91Provider) SendMessage(phone string, message string, channel string) (string, error) {
	switch channel {
	case SMSProvider:
		return t.SendSms(phone, message)
	default:
		return "", fmt.Errorf("msg91: channel type %q is not supported", channel)
	}
}

func (t *Msg91Provider) SendSms(phone string, message string) (string, error) {
	body := url.Values{
		"authkey":  {t.Config.AuthKey},
		"sender":   {t.Config.SenderId},
		"mobiles":  {phone},
		"message":  {message},
		"route":    {strconv.Itoa(4)},
		"response": {"json"},
	}

	// DLT template ID is only required for Indian users, to comply with
	// government regulations Indian users have to get their sms template
	// approved by DLT authorities before using it. DLT template ID is
	// provided by Authorities after the template is approved.
	if t.Config.DltTemplateId != nil && *t.Config.DltTemplateId != "" {
		body.Set("DLT_TE_ID", *t.Config.DltTemplateId)
	}

	bodyBuffer := bytes.NewBufferString(body.Encode())

	client := &http.Client{Timeout: defaultTimeout}
	req, err := http.NewRequest(http.MethodPost, t.APIPath, bodyBuffer)
	if err != nil {
		return "", fmt.Errorf("msg91 error: unable to create request %w", err)
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("msg91 error: failed to execute request %w", err)
	}
	defer utilities.SafeClose(res.Body)

	var resp Msg91Response
	if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
		return "", fmt.Errorf("msg91 error: failed to parse JSON response body (status code %v): %w", res.StatusCode, err)
	}

	if resp.Type != "success" {
		return resp.Message, fmt.Errorf("msg91 error: expected \"success\" but got %q with message %q (code: %v)", resp.Type, resp.Message, res.StatusCode)
	}

	return resp.Message, nil
}
