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
	defaultOTPIQApiBase = "https://api.otpiq.com/api"
)

type OTPIQProvider struct {
	Config  *conf.OTPIQProviderConfiguration
	APIPath string
}

type OTPIQError struct {
	Code    int    `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`

	// Credit-related fields (400 error)
	YourCredit     int `json:"yourCredit,omitempty"`
	RequiredCredit int `json:"requiredCredit,omitempty"`

	// Rate limit fields (429 error)
	WaitMinutes       int `json:"waitMinutes,omitempty"`
	MaxRequests       int `json:"maxRequests,omitempty"`
	TimeWindowMinutes int `json:"timeWindowMinutes,omitempty"`
}

type OTPIQResponse struct {
	Message string `json:"message,omitempty"`
	SMSID   string `json:"smsId,omitempty"`
	Credit  int    `json:"remainingCredit,omitempty"`
}

// Creates a SmsProvider with the OTPIQ Config
func NewOTPIQProvider(config conf.OTPIQProviderConfiguration) (SmsProvider, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	apiPath := defaultOTPIQApiBase + "/sms"
	return &OTPIQProvider{
		Config:  &config,
		APIPath: apiPath,
	}, nil
}

func (t *OTPIQProvider) SendMessage(phone, message, channel, otp string) (string, error) {
	switch channel {
	case SMSProvider, WhatsappProvider:
		return t.SendSms(phone, otp, channel)
	default:
		return t.SendSms(phone, otp, "auto")
	}
}
func (t *OTPIQProvider) SendSms(phone string, verificationCode string, channel string) (string, error) {
	resp := &OTPIQResponse{}
	errResp := &OTPIQError{}

	payload := map[string]string{
		"verificationCode": verificationCode,
		"provider":         channel,
		"smsType":          "verification",
		"phoneNumber":      phone,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	client := &http.Client{Timeout: defaultTimeout}
	r, err := http.NewRequest("POST", t.APIPath, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}

	r.Header.Add("Content-Type", "application/json")
	r.Header.Add("Authorization", "Bearer "+t.Config.ApiKey)

	res, err := client.Do(r)
	if err != nil {
		return "", err
	}
	defer utilities.SafeClose(res.Body)

	if res.StatusCode != http.StatusOK {
		if err := json.NewDecoder(res.Body).Decode(errResp); err != nil {
			return "", err
		}

		return "", fmt.Errorf("OTPIQ error: %s (code: %d)", errResp.Message, errResp.Code)
	}

	if err := json.NewDecoder(res.Body).Decode(resp); err != nil {
		return "", err
	}

	return resp.SMSID, nil
}
func (t *OTPIQProvider) VerifyOTP(phone, code string) error {
	return fmt.Errorf("VerifyOTP is not supported for OTPIQ")
}
