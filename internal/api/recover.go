package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/supabase/gotrue/internal/models"
	"github.com/supabase/gotrue/internal/storage"
)

// RecoverParams holds the parameters for a password recovery request
type RecoverParams struct {
	Email               string `json:"email"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
}

func (p *RecoverParams) Validate() error {
	if p.Email == "" {
		return unprocessableEntityError("Password recovery requires an email")
	}
	var err error
	if p.Email, err = validateEmail(p.Email); err != nil {
		return err
	}
	if err := validatePKCEParams(p.CodeChallengeMethod, p.CodeChallenge); err != nil {
		return err
	}
	return nil
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

	flowType := getFlowFromChallenge(params.CodeChallenge)
	if err := params.Validate(); err != nil {
		return err
	}

	var user *models.User
	aud := a.requestAud(ctx, r)

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
		mailer := a.Mailer(ctx)
		referrer := a.getReferrer(r)
		if isPKCEFlow(flowType) {
			codeChallengeMethod, terr := models.ParseCodeChallengeMethod(params.CodeChallengeMethod)
			if terr != nil {
				return terr
			}
			if terr := models.NewFlowStateWithUserID(tx, models.Recovery.String(), params.CodeChallenge, codeChallengeMethod, models.Recovery, &(user.ID)); terr != nil {
				return terr
			}
		}
		externalURL := getExternalHost(ctx)
		return a.sendPasswordRecovery(tx, user, mailer, config.SMTP.MaxFrequency, referrer, externalURL, config.Mailer.OtpLength, flowType)
	})
	if err != nil {
		if errors.Is(err, MaxFrequencyLimitError) {
			return tooManyRequestsError("For security purposes, you can only request this once every 60 seconds")
		}
		return internalServerError("Unable to process request").WithInternalError(err)
	}

	return sendJSON(w, http.StatusOK, map[string]string{})
}
