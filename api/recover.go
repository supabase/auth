package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
)

// RecoverParams holds the parameters for a password recovery request
type RecoverParams struct {
	Email string `json:"email"`
}

// Recover sends a recovery email
func (a *API) Recover(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	config := a.config
	params := &RecoverParams{}

	body, err := getBodyBytes(r)
	if err != nil {
		return badRequestError("Could not read body").WithInternalError(err)
	}

	if err := json.Unmarshal(body, params); err != nil {
		return badRequestError("Could not read verification params: %v", err)
	}

	if params.Email == "" {
		return unprocessableEntityError("Password recovery requires an email")
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

	err = db.Transaction(func(tx *storage.Connection) error {
		if terr := models.NewAuditLogEntry(r, tx, user, models.UserRecoveryRequestedAction, "", nil); terr != nil {
			return terr
		}
		identities, terr := models.FindIdentitiesByUser(tx, user)
		if terr != nil {
			return terr
		}
		hasEmailProvider := false
		for _, identity := range identities {
			if identity.Provider == "email" {
				hasEmailProvider = true
				break
			}
		}
		if !hasEmailProvider {
			if terr := models.NewAuditLogEntry(r, tx, user, models.UserRecoveryDeniedAction, "", nil); terr != nil {
				return terr
			}
			// don't send a recovery email if the user doesn't have an email identity
			return nil
		}
		mailer := a.Mailer(ctx)
		referrer := a.getReferrer(r)
		return a.sendPasswordRecovery(tx, user, mailer, config.SMTP.MaxFrequency, referrer, config.Mailer.OtpLength)
	})
	if err != nil {
		if errors.Is(err, MaxFrequencyLimitError) {
			return tooManyRequestsError("For security purposes, you can only request this once every 60 seconds")
		}
		return internalServerError("Unable to process request").WithInternalError(err)
	}

	return sendJSON(w, http.StatusOK, map[string]string{})
}
