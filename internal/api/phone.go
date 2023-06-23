package api

import (
	"context"
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/supabase/gotrue/internal/api/sms_provider"
	"github.com/supabase/gotrue/internal/crypto"
	"github.com/supabase/gotrue/internal/models"
	"github.com/supabase/gotrue/internal/storage"
)

const defaultSmsMessage = "Your code is %v"

var e164Format = regexp.MustCompile("^[1-9][0-9]{1,14}$")

const (
	phoneConfirmationOtp     = "confirmation"
	phoneReauthenticationOtp = "reauthentication"
)

func validatePhone(phone string) (string, error) {
	phone = formatPhoneNumber(phone)
	if isValid := validateE164Format(phone); !isValid {
		return "", unprocessableEntityError("Invalid phone number format (E.164 required)")
	}
	return phone, nil
}

// validateE164Format checks if phone number follows the E.164 format
func validateE164Format(phone string) bool {
	return e164Format.MatchString(phone)
}

// formatPhoneNumber removes "+" and whitespaces in a phone number
func formatPhoneNumber(phone string) string {
	return strings.ReplaceAll(strings.TrimPrefix(phone, "+"), " ", "")
}

// sendPhoneConfirmation sends an otp to the user's phone number
func (a *API) sendPhoneConfirmation(ctx context.Context, tx *storage.Connection, user *models.User, phone, otpType string, smsProvider sms_provider.SmsProvider, channel string) (string, error) {
	config := a.config

	var token *string
	var sentAt *time.Time

	includeFields := []string{}
	switch otpType {
	case phoneChangeVerification:
		token = &user.PhoneChangeToken
		sentAt = user.PhoneChangeSentAt
		user.PhoneChange = phone
		includeFields = append(includeFields, "phone_change", "phone_change_token", "phone_change_sent_at")
	case phoneConfirmationOtp:
		token = &user.ConfirmationToken
		sentAt = user.ConfirmationSentAt
		includeFields = append(includeFields, "confirmation_token", "confirmation_sent_at")
	case phoneReauthenticationOtp:
		token = &user.ReauthenticationToken
		sentAt = user.ReauthenticationSentAt
		includeFields = append(includeFields, "reauthentication_token", "reauthentication_sent_at")
	default:
		return "", internalServerError("invalid otp type")
	}

	if sentAt != nil && !sentAt.Add(config.Sms.MaxFrequency).Before(time.Now()) {
		return "", MaxFrequencyLimitError
	}
	oldToken := *token
	otp, err := crypto.GenerateOtp(config.Sms.OtpLength)
	if err != nil {
		return "", internalServerError("error generating otp").WithInternalError(err)
	}
	*token = fmt.Sprintf("%x", sha256.Sum224([]byte(phone+otp)))

	var message string
	if config.Sms.Template == "" {
		message = fmt.Sprintf(defaultSmsMessage, otp)
	} else {
		message = strings.Replace(config.Sms.Template, "{{ .Code }}", otp, -1)
	}

	messageID, serr := smsProvider.SendMessage(phone, message, channel)
	if serr != nil {
		*token = oldToken
		return messageID, serr
	}

	now := time.Now()

	switch otpType {
	case phoneConfirmationOtp:
		user.ConfirmationSentAt = &now
	case phoneChangeVerification:
		user.PhoneChangeSentAt = &now
	case phoneReauthenticationOtp:
		user.ReauthenticationSentAt = &now
	}

	return messageID, errors.Wrap(tx.UpdateOnly(user, includeFields...), "Database error updating user for confirmation")
}
