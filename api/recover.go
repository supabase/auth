package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/netlify/gotrue/api/sms_provider"
	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
)

// RecoverParams holds the parameters for a password recovery request
type RecoverParams struct {
	Email       string  `json:"email"`
	NewPassword *string `json:"new_password"`
	Phone       string  `json:"phone"`
}

// Recover sends a recovery email
func (a *API) Recover(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	config := a.getConfig(ctx)
	instanceID := getInstanceID(ctx)
	params := &RecoverParams{}
	jsonDecoder := json.NewDecoder(r.Body)
	err := jsonDecoder.Decode(params)
	if err != nil {
		return badRequestError("Could not read verification params: %v", err)
	}

	if params.Email == "" && params.Phone == "" {
		return unprocessableEntityError("Password recovery requires an email or a phone number")
	}

	if params.NewPassword != nil && len(*params.NewPassword) < config.PasswordMinLength {
		return invalidPasswordLengthError(config)
	}

	var user *models.User
	aud := a.requestAud(ctx, r)
	recoverErrorMessage := "If a user exists, you will receive an email with instructions on how to reset your password."
	if params.Email != "" {
		if err := a.validateEmail(ctx, params.Email); err != nil {
			return err
		}
		user, err = models.FindUserByEmailAndAudience(a.db, instanceID, params.Email, aud)
	} else if params.Phone != "" {
		params.Phone, err = a.validatePhone(params.Phone)
		if err != nil {
			return err
		}
		user, err = models.FindUserByPhoneAndAudience(a.db, instanceID, params.Phone, aud)
	}

	if err != nil {
		if models.IsNotFoundError(err) {
			return notFoundError(err.Error())
		}
		return internalServerError(recoverErrorMessage).WithInternalError(err)
	}

	err = a.db.Transaction(func(tx *storage.Connection) error {
		if terr := models.NewAuditLogEntry(tx, instanceID, user, models.UserRecoveryRequestedAction, nil); terr != nil {
			return terr
		}
		if params.NewPassword != nil {
			if terr := user.UpdateNewPassword(tx, *params.NewPassword); terr != nil {
				return internalServerError(recoverErrorMessage).WithInternalError(terr)
			}
		}

		if params.Email != "" {
			mailer := a.Mailer(ctx)
			referrer := a.getReferrer(r)
			return a.sendPasswordRecovery(tx, user, mailer, config.SMTP.MaxFrequency, referrer)
		} else if params.Phone != "" {
			smsProvider, err := sms_provider.GetSmsProvider(*config)
			if err != nil {
				return err
			}
			return a.sendPhoneConfirmation(ctx, tx, user, params.Phone, recoveryVerification, smsProvider)
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, MaxFrequencyLimitError) {
			return tooManyRequestsError("For security purposes, you can only request this once every 60 seconds")
		}
		return internalServerError(recoverErrorMessage).WithInternalError(err)
	}

	return sendJSON(w, http.StatusOK, &map[string]string{})
}
