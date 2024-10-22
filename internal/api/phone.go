package api

import (
	"bytes"
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
func (a *API) sendPhoneConfirmation(r *http.Request, tx *storage.Connection, user *models.User, phone, otpType string, channel string) (string, error) {
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
		return "", tooManyRequestsError(ErrorCodeOverSMSSendRateLimit, generateFrequencyLimitErrorMessage(sentAt, config.Sms.MaxFrequency))
	}

	now := time.Now()

	var otp, messageID string
	var err error

	if testOTP, ok := config.Sms.GetTestOTP(phone, now); ok {
		otp = testOTP
		messageID = "test-otp"
	}

	// not using test OTPs
	if otp == "" {
		// TODO(km): Deprecate this behaviour - rate limits should still be applied to autoconfirm
		if !config.Sms.Autoconfirm {
			// apply rate limiting before the sms is sent out
			if ok := a.limiterOpts.Phone.Allow(); !ok {
				return "", tooManyRequestsError(ErrorCodeOverSMSSendRateLimit, "SMS rate limit exceeded")
			}
		}
		otp, err = crypto.GenerateOtp(config.Sms.OtpLength)
		if err != nil {
			return "", internalServerError("error generating otp").WithInternalError(err)
		}
		if config.Hook.SendSMS.Enabled {
			input := hooks.SendSMSInput{
				User: user,
				SMS: hooks.SMS{
					OTP: otp,
				},
			}
			output := hooks.SendSMSOutput{}
			err := a.invokeHook(tx, r, &input, &output)
			if err != nil {
				return "", err
			}
		} else {
			smsProvider, err := sms_provider.GetSmsProvider(*config)
			if err != nil {
				return "", internalServerError("Unable to get SMS provider").WithInternalError(err)
			}
			message, err := generateSMSFromTemplate(config.Sms.SMSTemplate, otp)
			if err != nil {
				return "", internalServerError("error generating sms template").WithInternalError(err)
			}
			messageID, err := smsProvider.SendMessage(phone, message, channel, otp)
			if err != nil {
				return messageID, unprocessableEntityError(ErrorCodeSMSSendFailed, "Error sending %s OTP to provider: %v", otpType, err)
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

	if err := tx.UpdateOnly(user, includeFields...); err != nil {
		return messageID, errors.Wrap(err, "Database error updating user for phone")
	}

	var ottErr error
	switch otpType {
	case phoneConfirmationOtp:
		if err := models.CreateOneTimeToken(tx, user.ID, user.GetPhone(), user.ConfirmationToken, models.ConfirmationToken); err != nil {
			ottErr = errors.Wrap(err, "Database error creating confirmation token for phone")
		}
	case phoneChangeVerification:
		if err := models.CreateOneTimeToken(tx, user.ID, user.PhoneChange, user.PhoneChangeToken, models.PhoneChangeToken); err != nil {
			ottErr = errors.Wrap(err, "Database error creating phone change token")
		}
	case phoneReauthenticationOtp:
		if err := models.CreateOneTimeToken(tx, user.ID, user.GetPhone(), user.ReauthenticationToken, models.ReauthenticationToken); err != nil {
			ottErr = errors.Wrap(err, "Database error creating reauthentication token for phone")
		}
	}
	if ottErr != nil {
		return messageID, internalServerError("error creating one time token").WithInternalError(ottErr)
	}
	return messageID, nil
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
