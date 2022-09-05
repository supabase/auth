package api

import (
	"encoding/json"
	"net/http"

	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
)

// InviteParams are the parameters the Signup endpoint accepts
type InviteParams struct {
	Email string                 `json:"email"`
	Data  map[string]interface{} `json:"data"`
}

// Invite is the endpoint for inviting a new user
func (a *API) Invite(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	config := a.config
	adminUser := getAdminUser(ctx)
	params := &InviteParams{}

	body, err := getBodyBytes(r)
	if err != nil {
		return badRequestError("Could not read body").WithInternalError(err)
	}

	if err := json.Unmarshal(body, params); err != nil {
		return badRequestError("Could not read Invite params: %v", err)
	}

	if err := a.validateEmail(ctx, params.Email); err != nil {
		return err
	}

	aud := a.requestAud(ctx, r)
	user, err := models.FindUserByEmailAndAudience(a.db, params.Email, aud)
	if err != nil && !models.IsNotFoundError(err) {
		return internalServerError("Database error finding user").WithInternalError(err)
	}

	err = a.db.Transaction(func(tx *storage.Connection) error {
		if user != nil {
			if user.IsConfirmed() {
				return unprocessableEntityError(DuplicateEmailMsg)
			}
		} else {
			signupParams := SignupParams{
				Email:    params.Email,
				Data:     params.Data,
				Aud:      aud,
				Provider: "email",
			}
			user, err = a.signupNewUser(ctx, tx, &signupParams)
			if err != nil {
				return err
			}
		}

		if terr := models.NewAuditLogEntry(r, tx, adminUser, models.UserInvitedAction, "", map[string]interface{}{
			"user_id":    user.ID,
			"user_email": user.Email,
		}); terr != nil {
			return terr
		}

		mailer := a.Mailer(ctx)
		referrer := a.getReferrer(r)
		if err := sendInvite(tx, user, mailer, referrer, config.Mailer.OtpLength); err != nil {
			return internalServerError("Error inviting user").WithInternalError(err)
		}
		return nil
	})
	if err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, user)
}
