package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/supabase/gotrue/internal/api/sms_provider"
	"github.com/supabase/gotrue/internal/models"
	"github.com/supabase/gotrue/internal/storage"
)

// ResendConfirmationParams holds the parameters for a resend request
type ResendConfirmationParams struct {
	Type  string `json:"type"`
	Email string `json:"email"`
	Phone string `json:"phone"`
}

func (p *ResendConfirmationParams) Validate() error {
	switch p.Type {
	case signupVerification, emailChangeVerification, smsVerification, phoneChangeVerification:
		break
	default:
		// type does not match one of the above
		return badRequestError("Missing one of these types: signup, email_change, sms, phone_change")

	}
	if p.Email == "" && (p.Type == signupVerification || p.Type == emailChangeVerification) {
		return badRequestError("Type provided requires an email address")
	}
	if p.Phone == "" && (p.Type == smsVerification || p.Type == phoneChangeVerification) {
		return badRequestError("Type provided requires a phone number")
	}

	var err error
	if p.Email != "" && p.Phone != "" {
		return badRequestError("Only an email address or phone number should be provided.")
	} else if p.Email != "" {
		p.Email, err = validateEmail(p.Email)
		if err != nil {
			return err
		}
	} else if p.Phone != "" {
		p.Phone, err = validatePhone(p.Phone)
		if err != nil {
			return err
		}
	} else {
		// both email and phone are empty
		return badRequestError("Missing email address or phone number")
	}
	return nil
}

// Recover sends a recovery email
func (a *API) Resend(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	config := a.config
	params := &ResendConfirmationParams{}

	body, err := getBodyBytes(r)
	if err != nil {
		return badRequestError("Could not read body").WithInternalError(err)
	}

	if err := json.Unmarshal(body, params); err != nil {
		return badRequestError("Could not read params: %v", err)
	}

	if err := params.Validate(); err != nil {
		return err
	}

	var user *models.User
	aud := a.requestAud(ctx, r)
	if params.Email != "" {
		user, err = models.FindUserByEmailAndAudience(db, params.Email, aud)
	} else if params.Phone != "" {
		user, err = models.FindUserByPhoneAndAudience(db, params.Phone, aud)
	}

	if err != nil {
		if models.IsNotFoundError(err) {
			return sendJSON(w, http.StatusOK, map[string]string{})
		}
		return internalServerError("Unable to process request").WithInternalError(err)
	}

	switch params.Type {
	case signupVerification:
		if user.IsConfirmed() {
			// if the user's email is confirmed already, we don't need to send a confirmation email again
			return sendJSON(w, http.StatusOK, map[string]string{})
		}
	case smsVerification:
		if user.IsPhoneConfirmed() {
			// if the user's phone is confirmed already, we don't need to send a confirmation sms again
			return sendJSON(w, http.StatusOK, map[string]string{})
		}
	case emailChangeVerification:
		// do not resend if user doesn't have a new email address
		if user.EmailChange == "" {
			return sendJSON(w, http.StatusOK, map[string]string{})
		}
	case phoneChangeVerification:
		// do not resend if user doesn't have a new phone number
		if user.PhoneChange == "" {
			return sendJSON(w, http.StatusOK, map[string]string{})
		}
	}

	err = db.Transaction(func(tx *storage.Connection) error {
		mailer := a.Mailer(ctx)
		referrer := a.getReferrer(r)
		switch params.Type {
		case signupVerification:
			if terr := models.NewAuditLogEntry(r, tx, user, models.UserConfirmationRequestedAction, "", nil); terr != nil {
				return terr
			}
			return sendConfirmation(tx, user, mailer, config.SMTP.MaxFrequency, referrer, config.Mailer.OtpLength)
		case smsVerification:
			if terr := models.NewAuditLogEntry(r, tx, user, models.UserRecoveryRequestedAction, "", nil); terr != nil {
				return terr
			}
			smsProvider, terr := sms_provider.GetSmsProvider(*config)
			if terr != nil {
				return terr
			}
			return a.sendPhoneConfirmation(ctx, tx, user, params.Phone, phoneConfirmationOtp, smsProvider, sms_provider.SMSProvider)
		case emailChangeVerification:
			return a.sendEmailChange(tx, config, user, mailer, params.Email, referrer, config.Mailer.OtpLength)
		case phoneChangeVerification:
			smsProvider, terr := sms_provider.GetSmsProvider(*config)
			if terr != nil {
				return terr
			}
			return a.sendPhoneConfirmation(ctx, tx, user, params.Phone, phoneChangeVerification, smsProvider, sms_provider.SMSProvider)
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, MaxFrequencyLimitError) {
			until := time.Until(user.ConfirmationSentAt.Add(config.SMTP.MaxFrequency)) / time.Second
			return tooManyRequestsError("For security purposes, you can only request this once every %d seconds.", until)
		}
		return internalServerError("Unable to process request").WithInternalError(err)
	}

	return sendJSON(w, http.StatusOK, map[string]string{})
}
