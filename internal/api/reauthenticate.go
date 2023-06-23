package api

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"

	"github.com/supabase/gotrue/internal/api/sms_provider"
	"github.com/supabase/gotrue/internal/conf"
	"github.com/supabase/gotrue/internal/models"
	"github.com/supabase/gotrue/internal/storage"
)

const InvalidNonceMessage = "Nonce has expired or is invalid"

// Reauthenticate sends a reauthentication otp to either the user's email or phone
func (a *API) Reauthenticate(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	config := a.config

	user := getUser(ctx)
	email, phone := user.GetEmail(), user.GetPhone()

	if email == "" && phone == "" {
		return unprocessableEntityError("Reauthentication requires the user to have an email or a phone number")
	}

	if email != "" {
		if !user.IsConfirmed() {
			return badRequestError("Please verify your email first.")
		}
	} else if phone != "" {
		if !user.IsPhoneConfirmed() {
			return badRequestError("Please verify your phone first.")
		}
	}

	messageID := ""
	err := db.Transaction(func(tx *storage.Connection) error {
		if terr := models.NewAuditLogEntry(r, tx, user, models.UserReauthenticateAction, "", nil); terr != nil {
			return terr
		}
		if email != "" {
			mailer := a.Mailer(ctx)
			return a.sendReauthenticationOtp(tx, user, mailer, config.SMTP.MaxFrequency, config.Mailer.OtpLength)
		} else if phone != "" {
			smsProvider, terr := sms_provider.GetSmsProvider(*config)
			if terr != nil {
				return badRequestError("Error sending sms: %v", terr)
			}
			mID, err := a.sendPhoneConfirmation(ctx, tx, user, phone, phoneReauthenticationOtp, smsProvider, sms_provider.SMSProvider)
			if err != nil {
				return err
			}

			messageID = mID
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, MaxFrequencyLimitError) {
			return tooManyRequestsError("For security purposes, you can only request this once every 60 seconds")
		}
		return err
	}

	ret := map[string]any{}
	if messageID != "" {
		ret["message_id"] = messageID

	}

	return sendJSON(w, http.StatusOK, ret)
}

// verifyReauthentication checks if the nonce provided is valid
func (a *API) verifyReauthentication(nonce string, tx *storage.Connection, config *conf.GlobalConfiguration, user *models.User) error {
	if user.ReauthenticationToken == "" || user.ReauthenticationSentAt == nil {
		return badRequestError(InvalidNonceMessage)
	}
	var isValid bool
	if user.GetEmail() != "" {
		tokenHash := fmt.Sprintf("%x", sha256.Sum224([]byte(user.GetEmail()+nonce)))
		isValid = isOtpValid(tokenHash, user.ReauthenticationToken, user.ReauthenticationSentAt, config.Mailer.OtpExp)
	} else if user.GetPhone() != "" {
		if config.Sms.IsTwilioVerifyProvider() {
			smsProvider, _ := sms_provider.GetSmsProvider(*config)
			if err := smsProvider.(*sms_provider.TwilioVerifyProvider).VerifyOTP(string(user.Phone), nonce); err != nil {
				return expiredTokenError("Token has expired or is invalid").WithInternalError(err)
			}
			return nil
		} else {
			tokenHash := fmt.Sprintf("%x", sha256.Sum224([]byte(user.GetPhone()+nonce)))
			isValid = isOtpValid(tokenHash, user.ReauthenticationToken, user.ReauthenticationSentAt, config.Sms.OtpExp)
		}
	} else {
		return unprocessableEntityError("Reauthentication requires an email or a phone number")
	}
	if !isValid {
		return badRequestError(InvalidNonceMessage)
	}
	if err := user.ConfirmReauthentication(tx); err != nil {
		return internalServerError("Error during reauthentication").WithInternalError(err)
	}
	return nil
}
