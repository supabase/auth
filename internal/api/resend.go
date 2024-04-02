package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/supabase/auth/internal/api/sms_provider"
	"github.com/supabase/auth/internal/conf"
	mail "github.com/supabase/auth/internal/mailer"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

// ResendConfirmationParams holds the parameters for a resend request
type ResendConfirmationParams struct {
	Type  string `json:"type"`
	Email string `json:"email"`
	Phone string `json:"phone"`
}

func (p *ResendConfirmationParams) Validate(config *conf.GlobalConfiguration) error {
	switch p.Type {
	case mail.SignupVerification, mail.EmailChangeVerification, smsVerification, phoneChangeVerification:
		break
	default:
		// type does not match one of the above
		return badRequestError(ErrorCodeValidationFailed, "Missing one of these types: signup, email_change, sms, phone_change")

	}
	if p.Email == "" && p.Type == mail.SignupVerification {
		return badRequestError(ErrorCodeValidationFailed, "Type provided requires an email address")
	}
	if p.Phone == "" && p.Type == smsVerification {
		return badRequestError(ErrorCodeValidationFailed, "Type provided requires a phone number")
	}

	var err error
	if p.Email != "" && p.Phone != "" {
		return badRequestError(ErrorCodeValidationFailed, "Only an email address or phone number should be provided.")
	} else if p.Email != "" {
		if !config.External.Email.Enabled {
			return badRequestError(ErrorCodeEmailProviderDisabled, "Email logins are disabled")
		}
		p.Email, err = validateEmail(p.Email)
		if err != nil {
			return err
		}
	} else if p.Phone != "" {
		if !config.External.Phone.Enabled {
			return badRequestError(ErrorCodePhoneProviderDisabled, "Phone logins are disabled")
		}
		p.Phone, err = validatePhone(p.Phone)
		if err != nil {
			return err
		}
	} else {
		// both email and phone are empty
		return badRequestError(ErrorCodeValidationFailed, "Missing email address or phone number")
	}
	return nil
}

// Recover sends a recovery email
func (a *API) Resend(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	config := a.config
	params := &ResendConfirmationParams{}
	if err := retrieveRequestParams(r, params); err != nil {
		return err
	}

	if err := params.Validate(config); err != nil {
		return err
	}

	var user *models.User
	var err error
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
	case mail.SignupVerification:
		if user.IsConfirmed() {
			// if the user's email is confirmed already, we don't need to send a confirmation email again
			return sendJSON(w, http.StatusOK, map[string]string{})
		}
	case smsVerification:
		if user.IsPhoneConfirmed() {
			// if the user's phone is confirmed already, we don't need to send a confirmation sms again
			return sendJSON(w, http.StatusOK, map[string]string{})
		}
	case mail.EmailChangeVerification:
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

	messageID := ""
	err = db.Transaction(func(tx *storage.Connection) error {
		switch params.Type {
		case mail.SignupVerification:
			if terr := models.NewAuditLogEntry(r, tx, user, models.UserConfirmationRequestedAction, "", nil); terr != nil {
				return terr
			}
			// PKCE not implemented yet
			return a.sendConfirmation(r, tx, user, models.ImplicitFlow)
		case smsVerification:
			if terr := models.NewAuditLogEntry(r, tx, user, models.UserRecoveryRequestedAction, "", nil); terr != nil {
				return terr
			}
			smsProvider, terr := sms_provider.GetSmsProvider(*config)
			if terr != nil {
				return terr
			}
			mID, terr := a.sendPhoneConfirmation(ctx, r, tx, user, params.Phone, phoneConfirmationOtp, smsProvider, sms_provider.SMSProvider)
			if terr != nil {
				return terr
			}
			messageID = mID
		case mail.EmailChangeVerification:
			return a.sendEmailChange(r, tx, user, user.EmailChange, models.ImplicitFlow)
		case phoneChangeVerification:
			smsProvider, terr := sms_provider.GetSmsProvider(*config)
			if terr != nil {
				return terr
			}
			mID, terr := a.sendPhoneConfirmation(ctx, r, tx, user, user.PhoneChange, phoneChangeVerification, smsProvider, sms_provider.SMSProvider)
			if terr != nil {
				return terr
			}
			messageID = mID
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, MaxFrequencyLimitError) {
			reason := ErrorCodeOverEmailSendRateLimit
			if params.Type == smsVerification || params.Type == phoneChangeVerification {
				reason = ErrorCodeOverSMSSendRateLimit
			}

			until := time.Until(user.ConfirmationSentAt.Add(config.SMTP.MaxFrequency)) / time.Second
			return tooManyRequestsError(reason, "For security purposes, you can only request this once every %d seconds.", until)
		}
		return internalServerError("Unable to process request").WithInternalError(err)
	}

	ret := map[string]any{}
	if messageID != "" {
		ret["message_id"] = messageID
	}

	return sendJSON(w, http.StatusOK, ret)
}
