package sms_provider

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/supabase/auth/internal/conf"
)

const (
	// DefaultPlivoVerifyAPIBase is the default Plivo API base URL
	DefaultPlivoVerifyAPIBase = "https://api.plivo.com/v1"

	// VoiceChannel represents the Voice channel for OTP delivery
	VoiceChannel = "voice"

	// DefaultSessionTTL is the default time-to-live for session cache entries
	DefaultSessionTTL = 10 * time.Minute
)

// sessionEntry holds a cached session UUID and its expiration time
type plivoSessionEntry struct {
	SessionUUID string
	ExpiresAt   time.Time
}

// PlivoVerifyProvider implements the SmsProvider interface using Plivo Verify API.
// Unlike regular SMS providers, Plivo Verify:
//   - Generates and sends OTPs automatically (you don't provide the OTP)
//   - Requires tracking session_uuid for verification (not just phone number)
//   - Supports voice channel natively
type PlivoVerifyProvider struct {
	Config      *conf.PlivoVerifyProviderConfiguration
	APIBasePath string
	HTTPClient  *http.Client

	// Session cache: maps phone numbers to session UUIDs
	mu           sync.RWMutex
	sessionCache map[string]plivoSessionEntry
	sessionTTL   time.Duration
}

// PlivoVerifySessionResponse is the response from creating a verification session
type PlivoVerifySessionResponse struct {
	ApiID       string `json:"api_id"`
	Message     string `json:"message"`
	SessionUUID string `json:"session_uuid"`
	Error       string `json:"error,omitempty"`
}

// PlivoVerifyValidationResponse is the response from validating an OTP
type PlivoVerifyValidationResponse struct {
	ApiID   string `json:"api_id"`
	Message string `json:"message"`
	Error   string `json:"error,omitempty"`
}

// PlivoVerifyErrorResponse represents an error response from Plivo API
type PlivoVerifyErrorResponse struct {
	ApiID   string `json:"api_id"`
	Error   string `json:"error"`
	Message string `json:"message"`
}

// plivoCreateSessionRequest is the JSON request body for creating a verification session
type plivoCreateSessionRequest struct {
	Recipient  string `json:"recipient"`
	Channel    string `json:"channel"`
	AppUUID    string `json:"app_uuid"`
	Locale     string `json:"locale,omitempty"`
	BrandName  string `json:"brand_name,omitempty"`
	CodeLength int    `json:"code_length,omitempty"`
}

// plivoValidateSessionRequest is the JSON request body for validating an OTP
type plivoValidateSessionRequest struct {
	OTP string `json:"otp"`
}

// NewPlivoVerifyProvider creates a new Plivo Verify provider instance.
func NewPlivoVerifyProvider(config conf.PlivoVerifyProviderConfiguration) (SmsProvider, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	return &PlivoVerifyProvider{
		Config:       &config,
		APIBasePath:  DefaultPlivoVerifyAPIBase,
		HTTPClient:   &http.Client{Timeout: defaultTimeout},
		sessionCache: make(map[string]plivoSessionEntry),
		sessionTTL:   DefaultSessionTTL,
	}, nil
}

// SendMessage sends an OTP via the specified channel.
// Note: The 'message' and 'otp' parameters are ignored because Plivo Verify
// generates and sends its own OTP messages.
func (p *PlivoVerifyProvider) SendMessage(phone, message, channel, otp string) (string, error) {
	switch channel {
	case SMSProvider:
		return p.createSession(phone, SMSProvider)
	case VoiceChannel:
		return p.createSession(phone, VoiceChannel)
	default:
		return "", fmt.Errorf("plivo verify: unsupported channel: %s", channel)
	}
}

// createSession creates a new Plivo Verify session for the given phone and channel.
func (p *PlivoVerifyProvider) createSession(phone, channel string) (string, error) {
	// Normalize phone number (ensure it has + prefix for E.164)
	normalizedPhone := p.normalizePhoneNumber(phone)

	// Build request URL
	endpoint := fmt.Sprintf("%s/Account/%s/Verify/Session/", p.APIBasePath, p.Config.AuthID)

	// Build JSON request body
	reqBody := plivoCreateSessionRequest{
		Recipient: normalizedPhone,
		Channel:   channel,
		AppUUID:   p.Config.AppUUID,
	}

	if p.Config.Locale != "" {
		reqBody.Locale = p.Config.Locale
	}
	if p.Config.BrandName != "" {
		reqBody.BrandName = p.Config.BrandName
	}
	if p.Config.CodeLength > 0 {
		reqBody.CodeLength = p.Config.CodeLength
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("plivo verify: failed to marshal request: %w", err)
	}

	// Create request
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(jsonBody))
	if err != nil {
		return "", fmt.Errorf("plivo verify: failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(p.Config.AuthID, p.Config.AuthToken)

	// Execute request
	resp, err := p.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("plivo verify: failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("plivo verify: failed to read response: %w", err)
	}

	// Check for error status codes
	if resp.StatusCode >= 400 {
		var errResp PlivoVerifyErrorResponse
		if err := json.Unmarshal(body, &errResp); err == nil && errResp.Error != "" {
			return "", fmt.Errorf("plivo verify: %s - %s", errResp.Error, errResp.Message)
		}
		return "", fmt.Errorf("plivo verify: request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse success response
	var sessionResp PlivoVerifySessionResponse
	if err := json.Unmarshal(body, &sessionResp); err != nil {
		return "", fmt.Errorf("plivo verify: failed to parse response: %w", err)
	}

	if sessionResp.SessionUUID == "" {
		return "", fmt.Errorf("plivo verify: no session_uuid in response")
	}

	// Cache the session UUID for later verification
	p.cacheSession(normalizedPhone, sessionResp.SessionUUID)

	return sessionResp.SessionUUID, nil
}

// VerifyOTP validates the OTP code for the given phone number.
// This method looks up the cached session UUID for the phone number and
// validates the OTP against it.
func (p *PlivoVerifyProvider) VerifyOTP(phone, otp string) error {
	normalizedPhone := p.normalizePhoneNumber(phone)

	// Look up session UUID from cache
	sessionUUID, ok := p.getSession(normalizedPhone)
	if !ok {
		return fmt.Errorf("plivo verify: no active session for phone %s", normalizedPhone)
	}

	return p.validateSession(sessionUUID, otp)
}

// validateSession validates an OTP against a specific session.
func (p *PlivoVerifyProvider) validateSession(sessionUUID, otp string) error {
	// Build request URL
	endpoint := fmt.Sprintf("%s/Account/%s/Verify/Session/%s/", p.APIBasePath, p.Config.AuthID, sessionUUID)

	// Build JSON request body
	reqBody := plivoValidateSessionRequest{
		OTP: otp,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("plivo verify: failed to marshal validation request: %w", err)
	}

	// Create request
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(jsonBody))
	if err != nil {
		return fmt.Errorf("plivo verify: failed to create validation request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(p.Config.AuthID, p.Config.AuthToken)

	// Execute request
	resp, err := p.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("plivo verify: failed to send validation request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("plivo verify: failed to read validation response: %w", err)
	}

	// Check for error status codes
	if resp.StatusCode >= 400 {
		var errResp PlivoVerifyErrorResponse
		if err := json.Unmarshal(body, &errResp); err == nil && errResp.Error != "" {
			return fmt.Errorf("plivo verify: %s - %s", errResp.Error, errResp.Message)
		}
		return fmt.Errorf("plivo verify: validation failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse success response
	var validationResp PlivoVerifyValidationResponse
	if err := json.Unmarshal(body, &validationResp); err != nil {
		return fmt.Errorf("plivo verify: failed to parse validation response: %w", err)
	}

	// Check for success message
	if !strings.Contains(strings.ToLower(validationResp.Message), "validated successfully") {
		return fmt.Errorf("plivo verify: unexpected validation response: %s", validationResp.Message)
	}

	return nil
}

// cacheSession stores a session UUID for a phone number with TTL.
func (p *PlivoVerifyProvider) cacheSession(phone, sessionUUID string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.sessionCache[phone] = plivoSessionEntry{
		SessionUUID: sessionUUID,
		ExpiresAt:   time.Now().Add(p.sessionTTL),
	}
}

// getSession retrieves a cached session UUID for a phone number.
func (p *PlivoVerifyProvider) getSession(phone string) (string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	entry, ok := p.sessionCache[phone]
	if !ok {
		return "", false
	}

	// Check if session has expired
	if time.Now().After(entry.ExpiresAt) {
		return "", false
	}

	return entry.SessionUUID, true
}

// normalizePhoneNumber ensures the phone number is in E.164 format.
func (p *PlivoVerifyProvider) normalizePhoneNumber(phone string) string {
	phone = strings.TrimSpace(phone)
	if !strings.HasPrefix(phone, "+") {
		phone = "+" + phone
	}
	return phone
}
