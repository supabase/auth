package api

import (
	"context"
	"errors"

	"github.com/netlify/gotrue/api/sms_provider"
	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
)

// Recover sends a reauthentication otp to either the user's email or phone
func (a *API) Reauthenticate(ctx context.Context, conn *storage.Connection, user *models.User) error {
	config := a.getConfig(ctx)
	instanceID := getInstanceID(ctx)

	email, phone := user.GetEmail(), user.GetPhone()

	if email == "" && phone == "" {
		return unprocessableEntityError("Reauthentication requires an email or a phone number")
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

	err := conn.Transaction(func(tx *storage.Connection) error {
		if terr := models.NewAuditLogEntry(tx, instanceID, user, models.UserReauthenticateAction, nil); terr != nil {
			return terr
		}
		if email != "" {
			mailer := a.Mailer(ctx)
			return a.sendReauthenticationOtp(tx, user, mailer, config.SMTP.MaxFrequency)
		} else if phone != "" {
			smsProvider, err := sms_provider.GetSmsProvider(*config)
			if err != nil {
				return err
			}
			return a.sendPhoneConfirmation(ctx, tx, user, phone, recoveryVerification, smsProvider)
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, MaxFrequencyLimitError) {
			return tooManyRequestsError("For security purposes, you can only request this once every 60 seconds")
		}
		return internalServerError("Reauthentication failed.").WithInternalError(err)
	}

	return nil
}
