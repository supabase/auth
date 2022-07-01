package api

import (
	"context"
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/netlify/gotrue/api/sms_provider"
	"github.com/netlify/gotrue/crypto"
	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
	"github.com/pkg/errors"
)

const e164Format = `^[1-9]\d{1,14}$`
const defaultSmsMessage = "Your code is %v"

const (
	phoneConfirmationOtp     = "confirmation"
	phoneReauthenticationOtp = "reauthentication"
)

func (a *API) validatePhone(phone string) (string, error) {
	phone = a.formatPhoneNumber(phone)
	if isValid := a.validateE164Format(phone); !isValid {
		return "", unprocessableEntityError("Invalid phone number format")
	}
	return phone, nil
}

// validateE164Format checks if phone number follows the E.164 format
func (a *API) validateE164Format(phone string) bool {
	// match should never fail as long as regexp is valid
	matched, _ := regexp.Match(e164Format, []byte(phone))
	return matched
}

// formatPhoneNumber removes "+" and whitespaces in a phone number
func (a *API) formatPhoneNumber(phone string) string {
	return strings.ReplaceAll(strings.Trim(phone, "+"), " ", "")
}

// sendPhoneConfirmation sends an otp to the user's phone number
func (a *API) sendPhoneConfirmation(ctx context.Context, tx *storage.Connection, user *models.User, phone, otpType string, smsProvider sms_provider.SmsProvider) error {
	config := a.getConfig(ctx)

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
		return internalServerError("invalid otp type")
	}

	if sentAt != nil && !sentAt.Add(config.Sms.MaxFrequency).Before(time.Now()) {
		return MaxFrequencyLimitError
	}

	oldToken := *token
	otp, err := crypto.GenerateOtp(config.Sms.OtpLength)
	if err != nil {
		return internalServerError("error generating otp").WithInternalError(err)
	}
	*token = fmt.Sprintf("%x", sha256.Sum224([]byte(phone+otp)))

	var message string
	if config.Sms.Template == "" {
		message = fmt.Sprintf(defaultSmsMessage, otp)
	} else {
		message = strings.Replace(config.Sms.Template, "{{ .Code }}", otp, -1)
	}

	if serr := smsProvider.SendSms(phone, message); serr != nil {
		*token = oldToken
		return serr
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

	return errors.Wrap(tx.UpdateOnly(user, includeFields...), "Database error updating user for confirmation")
}
