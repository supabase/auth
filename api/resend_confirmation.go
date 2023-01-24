package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
)

// RecoverParams holds the parameters for a password recovery request
type SendConfirmationParams struct {
	Email string `json:"email"`
}

// Recover sends a recovery email
func (a *API) SendConfirmation(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	config := a.config
	params := &SendConfirmationParams{}

	body, err := getBodyBytes(r)
	if err != nil {
		return badRequestError("Could not read body").WithInternalError(err)
	}

	if err := json.Unmarshal(body, params); err != nil {
		return badRequestError("Could not read verification params: %v", err)
	}

	if params.Email == "" {
		return unprocessableEntityError("Resend email confirmation requires an email")
	}

	var user *models.User
	aud := a.requestAud(ctx, r)

	params.Email, err = a.validateEmail(ctx, params.Email)
	if err != nil {
		return err
	}
	user, err = models.FindUserByEmailAndAudience(db, params.Email, aud)

	if err != nil {
		if models.IsNotFoundError(err) {
			return sendJSON(w, http.StatusOK, map[string]string{})
		}
		return internalServerError("Unable to process request").WithInternalError(err)
	}

	if user.IsConfirmed() {
		// if the user is confirmed already, we don't need to send a confirmation email again
		return sendJSON(w, http.StatusOK, map[string]string{})
	}

	err = db.Transaction(func(tx *storage.Connection) error {
		if terr := models.NewAuditLogEntry(r, tx, user, models.UserConfirmationRequestedAction, "", nil); terr != nil {
			return terr
		}
		mailer := a.Mailer(ctx)
		referrer := a.getReferrer(r)
		return sendConfirmation(tx, user, mailer, config.SMTP.MaxFrequency, referrer, config.Mailer.OtpLength)
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
