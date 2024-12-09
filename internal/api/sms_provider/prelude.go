package sms_provider

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/utilities"
)

const (
	preludeServiceApiBase = "https://api.prelude.dev/v2"
)

type PreludeProvider struct {
	Config  *conf.PreludeProviderConfiguration
	APIPath string
}

type PreludeVerificationRequest struct {
	Target struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"target"`
	Signals *PreludeSignals `json:"signals,omitempty"`
	Options *PreludeOptions `json:"options,omitempty"`
}

type PreludeSignals struct {
	IP             string `json:"ip,omitempty"`
	DeviceID       string `json:"device_id,omitempty"`
	DevicePlatform string `json:"device_platform,omitempty"`
	DeviceModel    string `json:"device_model,omitempty"`
	OSVersion      string `json:"os_version,omitempty"`
	AppVersion     string `json:"app_version,omitempty"`
	IsTrustedUser  string `json:"is_trusted_user,omitempty"`
}

type PreludeOptions struct {
	TemplateID string `json:"template_id,omitempty"`
	Locale     string `json:"locale,omitempty"`
	SenderID   string `json:"sender_id,omitempty"`
}

type PreludeVerificationResponse struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	Method    string `json:"method"`
	ErrorCode string `json:"error_code,omitempty"`
}

type PreludeVerificationCheckRequest struct {
	Target struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"target"`
	Code string `json:"code"`
}

type PreludeVerificationCheckResponse struct {
	Status    string                 `json:"status"`
	ID        string                 `json:"id"`
	Metadata  map[string]interface{} `json:"metadata"`
	RequestID string                 `json:"request_id"`
}

func NewPreludeProvider(config conf.PreludeProviderConfiguration) (SmsProvider, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return &PreludeProvider{
		Config:  &config,
		APIPath: preludeServiceApiBase + "/verification",
	}, nil
}

func (p *PreludeProvider) SendMessage(phone, message, channel, otp string) (string, error) {
	switch channel {
	case SMSProvider:
		return p.SendSms(phone, message, channel)
	default:
		return "", fmt.Errorf("channel type %q is not supported for Prelude", channel)
	}
}

func (p *PreludeProvider) SendSms(phone, message, channel string) (string, error) {
	reqBody := PreludeVerificationRequest{}
	reqBody.Target.Type = "phone_number"
	reqBody.Target.Value = "+" + phone

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	client := &http.Client{Timeout: defaultTimeout}
	r, err := http.NewRequest("POST", p.APIPath, bytes.NewBuffer(jsonBody))
	if err != nil {
		return "", err
	}

	r.Header.Add("Content-Type", "application/json")
	r.Header.Add("Authorization", "Bearer "+p.Config.AuthToken)

	res, err := client.Do(r)
	if err != nil {
		return "", err
	}
	defer utilities.SafeClose(res.Body)

	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("prelude API error: %d", res.StatusCode)
	}

	resp := &PreludeVerificationResponse{}
	if err := json.NewDecoder(res.Body).Decode(resp); err != nil {
		return "", err
	}

	if resp.Status == "blocked" {
		return "", fmt.Errorf("verification blocked by Prelude")
	}

	return resp.ID, nil
}

func (p *PreludeProvider) VerifyOTP(phone, code string) error {
	reqBody := PreludeVerificationCheckRequest{}
	reqBody.Target.Type = "phone_number"
	reqBody.Target.Value = "+" + phone
	reqBody.Code = code

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	verifyPath := preludeServiceApiBase + "/verification/check"
	client := &http.Client{Timeout: defaultTimeout}
	r, err := http.NewRequest("POST", verifyPath, bytes.NewBuffer(jsonBody))
	if err != nil {
		return err
	}

	r.Header.Add("Content-Type", "application/json")
	r.Header.Add("Authorization", "Bearer "+p.Config.AuthToken)

	res, err := client.Do(r)
	if err != nil {
		return err
	}
	defer utilities.SafeClose(res.Body)

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("prelude API error: %d", res.StatusCode)
	}

	resp := &PreludeVerificationCheckResponse{}
	if err := json.NewDecoder(res.Body).Decode(resp); err != nil {
		return err
	}

	switch resp.Status {
	case "success":
		return nil
	case "failure":
		return fmt.Errorf("invalid verification code")
	case "expired_or_not_found":
		return fmt.Errorf("verification code expired or not found")
	default:
		return fmt.Errorf("unexpected verification status: %s", resp.Status)
	}
}
