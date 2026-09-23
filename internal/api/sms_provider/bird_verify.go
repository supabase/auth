package sms_provider

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/utilities"
)

// Bird API keys carry their region: bk_{region}_{token}. The pattern rather
// than a fixed list of regions so a new Bird region needs no change here.
var birdRegionPattern = regexp.MustCompile(`^[a-z]{2}[0-9]+$`)

type BirdVerifyProvider struct {
	Config  *conf.BirdVerifyProviderConfiguration
	APIPath string
}

type BirdVerifyTo struct {
	PhoneNumber string `json:"phone_number"`
}

type BirdVerificationRequest struct {
	To      BirdVerifyTo            `json:"to"`
	Options BirdVerificationOptions `json:"options"`
}

type BirdVerificationOptions struct {
	Channels []string `json:"channels"`
}

type BirdVerificationCheckRequest struct {
	To   BirdVerifyTo `json:"to"`
	Code string       `json:"code"`
}

type BirdVerificationResponse struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

// See: https://bird.com/docs/guides/verify/overview
type BirdVerificationCheckResponse struct {
	Success bool   `json:"success"`
	Reason  string `json:"reason"`
}

type BirdErrResponse struct {
	Type    string `json:"type"`
	Code    string `json:"code"`
	Name    string `json:"name"`
	Message string `json:"message"`
	// Bird resolves the next step for a given error code server-side, so the
	// remediation travels with the response instead of being mapped here.
	Remediation string `json:"remediation"`
	DocURL      string `json:"doc_url"`
	RequestID   string `json:"request_id"`
	StatusCode  int    `json:"-"`
}

func (e BirdErrResponse) Error() string {
	msg := "bird error: " + e.Message
	if e.Remediation != "" {
		msg += " " + e.Remediation
	}
	details := []string{
		fmt.Sprintf("code %s", e.Code),
		fmt.Sprintf("HTTP %d", e.StatusCode),
	}
	if e.RequestID != "" {
		details = append(details, "request id "+e.RequestID)
	}
	if e.DocURL != "" {
		details = append(details, "more information: "+e.DocURL)
	}
	return msg + " (" + strings.Join(details, ", ") + ")"
}

// Bird nests every error under an "error" key.
type birdErrEnvelope struct {
	Error BirdErrResponse `json:"error"`
}

// Creates a SmsProvider with the Bird Verify Config
func NewBirdVerifyProvider(config conf.BirdVerifyProviderConfiguration) (SmsProvider, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	baseURL := strings.TrimSuffix(config.ApiUrl, "/")
	if baseURL == "" {
		region := config.Region
		if region == "" {
			region = birdRegionFromApiKey(config.ApiKey)
		}
		if region == "" {
			return nil, fmt.Errorf("cannot determine Bird region: set GOTRUE_SMS_BIRD_VERIFY_REGION or GOTRUE_SMS_BIRD_VERIFY_API_URL, or use a bk_{region}_{token} API key")
		}
		baseURL = "https://" + region + ".platform.bird.com"
	}

	return &BirdVerifyProvider{
		Config:  &config,
		APIPath: baseURL + "/v1/verify/verifications",
	}, nil
}

// birdRegionFromApiKey extracts the region from a bk_{region}_{token} key, or "".
func birdRegionFromApiKey(key string) string {
	parts := strings.SplitN(key, "_", 3)
	if len(parts) < 3 || parts[0] != "bk" || parts[2] == "" {
		return ""
	}
	if !birdRegionPattern.MatchString(parts[1]) {
		return ""
	}
	return parts[1]
}

func (b *BirdVerifyProvider) SendMessage(phone, message, channel, otp string) (string, error) {
	switch channel {
	case SMSProvider, WhatsappProvider:
		return b.SendSms(phone, message, channel)
	default:
		return "", fmt.Errorf("channel type %q is not supported for Bird Verify", channel)
	}
}

// Bird Verify generates and delivers the passcode itself, so the message
// rendered by GoTrue is unused: only the recipient and the channel are sent.
// The channel is pinned rather than left to the workspace's configured order,
// which would let a request for SMS be delivered over WhatsApp instead.
func (b *BirdVerifyProvider) SendSms(phone, message, channel string) (string, error) {
	res, err := b.post(b.APIPath, BirdVerificationRequest{
		To:      BirdVerifyTo{PhoneNumber: normalizeBirdPhone(phone)},
		Options: BirdVerificationOptions{Channels: []string{channel}},
	})
	if err != nil {
		return "", err
	}
	defer utilities.SafeClose(res.Body)

	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusCreated && res.StatusCode != http.StatusAccepted {
		return "", birdError(res)
	}

	resp := &BirdVerificationResponse{}
	if err := json.NewDecoder(res.Body).Decode(resp); err != nil {
		return "", err
	}
	return resp.ID, nil
}

func (b *BirdVerifyProvider) VerifyOTP(phone, code string) error {
	res, err := b.post(b.APIPath+"/check", BirdVerificationCheckRequest{
		To:   BirdVerifyTo{PhoneNumber: normalizeBirdPhone(phone)},
		Code: code,
	})
	if err != nil {
		return err
	}
	defer utilities.SafeClose(res.Body)

	if res.StatusCode != http.StatusOK {
		return birdError(res)
	}

	resp := &BirdVerificationCheckResponse{}
	if err := json.NewDecoder(res.Body).Decode(resp); err != nil {
		return err
	}
	// An incorrect passcode is a normal 200 with success false, not an error status.
	if !resp.Success {
		return fmt.Errorf("bird verification failed: %v", resp.Reason)
	}
	return nil
}

func (b *BirdVerifyProvider) post(path string, payload any) (*http.Response, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: defaultTimeout}
	r, err := http.NewRequest("POST", path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	r.Header.Add("Content-Type", "application/json")
	r.Header.Add("Authorization", "Bearer "+b.Config.ApiKey)
	return client.Do(r)
}

func birdError(res *http.Response) error {
	envelope := &birdErrEnvelope{}
	if err := json.NewDecoder(res.Body).Decode(envelope); err != nil {
		return fmt.Errorf("bird error: HTTP %d", res.StatusCode)
	}
	envelope.Error.StatusCode = res.StatusCode
	return envelope.Error
}

// GoTrue stores phone numbers without the leading "+"; Bird requires E.164.
func normalizeBirdPhone(phone string) string {
	if strings.HasPrefix(phone, "+") {
		return phone
	}
	return "+" + phone
}
