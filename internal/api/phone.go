package api

import (
	"bytes"
	"context"
	"net/http"
	"regexp"
	"strings"
	"text/template"
	"time"

	"github.com/supabase/auth/internal/hooks"

	"github.com/pkg/errors"
	"github.com/supabase/auth/internal/api/sms_provider"
	"github.com/supabase/auth/internal/crypto"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

var e164Format = regexp.MustCompile("^[1-9][0-9]{1,14}$")

const (
	phoneConfirmationOtp     = "confirmation"
	phoneReauthenticationOtp = "reauthentication"
)

func validatePhone(phone string) (string, error) {
	phone = formatPhoneNumber(phone)
	if isValid := validateE164Format(phone); !isValid {
		return "", badRequestError(ErrorCodeValidationFailed, "Invalid phone number format (E.164 required)")
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
func (a *API) sendPhoneConfirmation(ctx context.Context, r *http.Request, tx *storage.Connection, user *models.User, phone, otpType string, smsProvider sms_provider.SmsProvider, channel string) (string, error) {
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

	// intentionally keeping this before the test OTP, so that the behavior
	// of regular and test OTPs is similar
	if sentAt != nil && !sentAt.Add(config.Sms.MaxFrequency).Before(time.Now()) {
		return "", MaxFrequencyLimitError
	}

	now := time.Now()

	var otp, messageID string
	var err error

	if testOTP, ok := config.Sms.GetTestOTP(phone, now); ok {
		otp = testOTP
		messageID = "test-otp"
	}

	if otp == "" { // not using test OTPs
		otp, err = crypto.GenerateOtp(config.Sms.OtpLength)
		if err != nil {
			return "", internalServerError("error generating otp").WithInternalError(err)
		}

		message, err := generateSMSFromTemplate(config.Sms.SMSTemplate, otp)
		if err != nil {
			return "", err
		}
		if config.Hook.SendSMS.Enabled {
			input := hooks.SendSMSInput{
				UserID: user.ID,
				Phone:  user.Phone.String(),
				OTP:    otp,
			}
			output := hooks.SendSMSOutput{}
			err := a.invokeHook(tx, r, &input, &output, a.config.Hook.SendSMS.URI)
			if err != nil {
				return "", err
			}
		} else {

			messageID, err = smsProvider.SendMessage(phone, message, channel, otp)
			if err != nil {
				return messageID, err
			}
		}
	}

	*token = crypto.GenerateTokenHash(phone, otp)

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

func generateSMSFromTemplate(SMSTemplate *template.Template, otp string) (string, error) {
	var message bytes.Buffer
	if err := SMSTemplate.Execute(&message, struct {
		Code string
	}{Code: otp}); err != nil {
		return "", err
	}
	return message.String(), nil
}
