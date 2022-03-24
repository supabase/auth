package api

import (
	"errors"
	"net/http"

	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/api/sms_provider"
	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
)

// Recover sends a reauthentication otp to either the user's email or phone
func (a *API) Reauthenticate(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	config := a.getConfig(ctx)
	instanceID := getInstanceID(ctx)

	claims := getClaims(ctx)
	userID, err := uuid.FromString(claims.Subject)
	if err != nil {
		return badRequestError("Could not read User ID claim")
	}
	user, err := models.FindUserByID(a.db, userID)
	if err != nil {
		if models.IsNotFoundError(err) {
			return notFoundError(err.Error())
		}
		return internalServerError("Database error finding user").WithInternalError(err)
	}

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

	err = a.db.Transaction(func(tx *storage.Connection) error {
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
