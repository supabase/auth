package api

import (
	"context"
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
	phoneChangeOtp       = "phone_change"
	phoneConfirmationOtp = "confirmation"
)

func (a *API) validatePhone(phone string) (string, error) {
	phone = a.formatPhoneNumber(phone)
	if isValid := a.validateE164Format(phone); !isValid {
		return "", unprocessableEntityError("Invalid phone number format")
	}
	return phone, nil
}

// validateE165Format checks if phone number follows the E.164 format
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
	var tokenDbField, sentAtDbField string

	if otpType == phoneConfirmationOtp {
		token = &user.ConfirmationToken
		sentAt = user.ConfirmationSentAt
		tokenDbField, sentAtDbField = "confirmation_token", "confirmation_sent_at"
	} else if otpType == phoneChangeOtp {
		token = &user.PhoneChangeToken
		sentAt = user.PhoneChangeSentAt
		tokenDbField, sentAtDbField = "phone_change_token", "phone_change_sent_at"
	} else {
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
	*token = otp

	var message string
	if config.Sms.Template == "" {
		message = fmt.Sprintf(defaultSmsMessage, *token)
	} else {
		message = strings.Replace(config.Sms.Template, "{{ .Code }}", *token, -1)
	}

	if serr := smsProvider.SendSms(phone, message); serr != nil {
		*token = oldToken
		return serr
	}

	now := time.Now()
	if otpType == phoneConfirmationOtp {
		user.ConfirmationSentAt = &now
	} else if otpType == phoneChangeOtp {
		user.PhoneChangeSentAt = &now
	}

	return errors.Wrap(tx.UpdateOnly(user, tokenDbField, sentAtDbField), "Database error updating user for confirmation")
}
