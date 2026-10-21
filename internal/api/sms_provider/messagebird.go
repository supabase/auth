package sms_provider

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/utilities"
)

const (
	defaultMessagebirdApiBase = "https://rest.messagebird.com"
	// The OTP template Bird stocks in every workspace. A template send needs no
	// sender: Bird picks one for the destination, which is what lets a workspace
	// that owns no number send at all.
	birdOtpTemplate = "bird_otp_verification"
)

// Bird's platform keys carry their region: bk_{region}_{token}. Matching the
// shape rather than a fixed list of regions means a new region needs no change
// here, and a legacy MessageBird access key never matches.
var birdKeyPattern = regexp.MustCompile(`^bk_([a-z]{2}[0-9]+)_.+$`)

type MessagebirdProvider struct {
	Config  *conf.MessagebirdProviderConfiguration
	APIPath string
}

type MessagebirdResponseRecipients struct {
	TotalSentCount int `json:"totalSentCount"`
}

type MessagebirdResponse struct {
	ID         string                        `json:"id"`
	Recipients MessagebirdResponseRecipients `json:"recipients"`
}

type MessagebirdError struct {
	Code        int    `json:"code"`
	Description string `json:"description"`
	Parameter   string `json:"parameter"`
}

type MessagebirdErrResponse struct {
	Errors []MessagebirdError `json:"errors"`
}

func (t MessagebirdErrResponse) Error() string {
	return t.Errors[0].Description
}

// Bird's platform nests every error under an "error" key, unlike the legacy
// API's "errors" array.
type birdErrEnvelope struct {
	Error BirdErrResponse `json:"error"`
}

type BirdErrResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	// Bird resolves the next step for a given error code server-side, so the
	// remediation travels with the response instead of being mapped here.
	Remediation string `json:"remediation"`
	RequestID   string `json:"request_id"`
	StatusCode  int    `json:"-"`
}

func (e BirdErrResponse) Error() string {
	msg := "bird error: " + e.Message
	if e.Remediation != "" {
		msg += " " + e.Remediation
	}
	details := fmt.Sprintf("code %s, HTTP %d", e.Code, e.StatusCode)
	if e.RequestID != "" {
		details += ", request id " + e.RequestID
	}
	return msg + " (" + details + ")"
}

type birdSmsTemplate struct {
	Name       string            `json:"name"`
	Parameters map[string]string `json:"parameters"`
}

type birdSmsRequest struct {
	To       string           `json:"to"`
	From     string           `json:"from,omitempty"`
	Text     string           `json:"text,omitempty"`
	Category string           `json:"category,omitempty"`
	Template *birdSmsTemplate `json:"template,omitempty"`
}

type birdSmsResponse struct {
	ID string `json:"id"`
}

// Creates a SmsProvider with the Messagebird Config
func NewMessagebirdProvider(config conf.MessagebirdProviderConfiguration) (SmsProvider, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	apiPath := defaultMessagebirdApiBase + "/messages"
	if region := birdRegionFromAccessKey(config.AccessKey); region != "" {
		apiPath = "https://" + region + ".platform.bird.com/v1/sms/messages"
	}
	return &MessagebirdProvider{
		Config:  &config,
		APIPath: apiPath,
	}, nil
}

// birdRegionFromAccessKey returns the region of a bk_{region}_{token} key, or ""
// for a legacy MessageBird access key.
func birdRegionFromAccessKey(key string) string {
	m := birdKeyPattern.FindStringSubmatch(key)
	if m == nil {
		return ""
	}
	return m[1]
}

func (t *MessagebirdProvider) isBirdPlatform() bool {
	return birdRegionFromAccessKey(t.Config.AccessKey) != ""
}

func (t *MessagebirdProvider) SendMessage(phone, message, channel, otp string) (string, error) {
	switch channel {
	case SMSProvider:
		return t.SendSms(phone, message, otp)
	default:
		return "", fmt.Errorf("channel type %q is not supported for Messagebird", channel)
	}
}

// Send an SMS containing the OTP with Messagebird's API
func (t *MessagebirdProvider) SendSms(phone, message, otp string) (string, error) {
	if t.isBirdPlatform() {
		return t.sendBird(phone, message, otp)
	}
	return t.sendLegacy(phone, message)
}

// Bird's platform requires a sender the workspace owns or has registered, which
// a workspace that has just signed up has neither of. A send from Bird's stocked
// OTP template needs no sender, so an unset originator selects it: GoTrue still
// generates and checks the code, and only the message wording comes from Bird.
func (t *MessagebirdProvider) sendBird(phone, message, otp string) (string, error) {
	payload := birdSmsRequest{To: "+" + strings.TrimPrefix(phone, "+")}
	if t.Config.Originator != "" {
		payload.From = t.Config.Originator
		payload.Text = message
		payload.Category = "authentication"
	} else {
		payload.Template = &birdSmsTemplate{
			Name:       birdOtpTemplate,
			Parameters: map[string]string{"code": otp},
		}
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	client := &http.Client{Timeout: defaultTimeout}
	r, err := http.NewRequest("POST", t.APIPath, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	r.Header.Add("Content-Type", "application/json")
	r.Header.Add("Authorization", "Bearer "+t.Config.AccessKey)
	res, err := client.Do(r)
	if err != nil {
		return "", err
	}
	defer utilities.SafeClose(res.Body)

	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusCreated && res.StatusCode != http.StatusAccepted {
		envelope := &birdErrEnvelope{}
		if err := json.NewDecoder(res.Body).Decode(envelope); err != nil {
			return "", fmt.Errorf("bird error: HTTP %d", res.StatusCode)
		}
		envelope.Error.StatusCode = res.StatusCode
		return "", envelope.Error
	}

	resp := &birdSmsResponse{}
	if err := json.NewDecoder(res.Body).Decode(resp); err != nil {
		return "", err
	}
	return resp.ID, nil
}

func (t *MessagebirdProvider) sendLegacy(phone string, message string) (string, error) {
	body := url.Values{
		"originator": {t.Config.Originator},
		"body":       {message},
		"recipients": {phone},
		"type":       {"sms"},
		"datacoding": {"unicode"},
	}

	client := &http.Client{Timeout: defaultTimeout}
	r, err := http.NewRequest("POST", t.APIPath, strings.NewReader(body.Encode()))
	if err != nil {
		return "", err
	}
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Add("Authorization", "AccessKey "+t.Config.AccessKey)
	res, err := client.Do(r)
	if err != nil {
		return "", err
	}

	if res.StatusCode == http.StatusBadRequest || res.StatusCode == http.StatusForbidden || res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusUnprocessableEntity {
		resp := &MessagebirdErrResponse{}
		if err := json.NewDecoder(res.Body).Decode(resp); err != nil {
			return "", err
		}
		return "", resp
	}
	defer utilities.SafeClose(res.Body)

	// validate sms status
	resp := &MessagebirdResponse{}
	derr := json.NewDecoder(res.Body).Decode(resp)
	if derr != nil {
		return "", derr
	}

	if resp.Recipients.TotalSentCount == 0 {
		return "", fmt.Errorf("messagebird error: total sent count is 0")
	}

	return resp.ID, nil
}

func (t *MessagebirdProvider) VerifyOTP(phone, code string) error {
	return fmt.Errorf("VerifyOTP is not supported for Messagebird")
}
