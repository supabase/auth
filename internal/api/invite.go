package api

import (
	"encoding/json"
	"net/http"

	"github.com/fatih/structs"
	"github.com/supabase/gotrue/internal/api/provider"
	"github.com/supabase/gotrue/internal/models"
	"github.com/supabase/gotrue/internal/storage"
)

// InviteParams are the parameters the Signup endpoint accepts
type InviteParams struct {
	Email               string                 `json:"email"`
	Data                map[string]interface{} `json:"data"`
	CodeChallenge       string                 `json:"code_challenge"`
	CodeChallengeMethod string                 `json:"code_challenge_method"`
}

func (p *InviteParams) Validate() error {
	if p.Email == "" {
		return unprocessableEntityError("Invitation email is required")
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

// Invite is the endpoint for inviting a new user
func (a *API) Invite(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
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

	var codeChallengeMethod models.CodeChallengeMethod
	flowType := getFlowFromChallenge(params.CodeChallenge)
	if err := params.Validate(); err != nil {
		return err
	}

	aud := a.requestAud(ctx, r)
	user, err := models.FindUserByEmailAndAudience(db, params.Email, aud)
	if err != nil && !models.IsNotFoundError(err) {
		return internalServerError("Database error finding user").WithInternalError(err)
	}

	err = db.Transaction(func(tx *storage.Connection) error {
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
			user, err = a.signupNewUser(ctx, tx, &signupParams, false /* <- isSSOUser */)
			if err != nil {
				return err
			}
			identity, err := a.createNewIdentity(tx, user, "email", structs.Map(provider.Claims{
				Subject: user.ID.String(),
				Email:   user.GetEmail(),
			}))
			if err != nil {
				return err
			}
			user.Identities = []models.Identity{*identity}
		}

		if terr := models.NewAuditLogEntry(r, tx, adminUser, models.UserInvitedAction, "", map[string]interface{}{
			"user_id":    user.ID,
			"user_email": user.Email,
		}); terr != nil {
			return terr
		}

		mailer := a.Mailer(ctx)
		referrer := a.getReferrer(r)
		if isPKCEFlow(flowType) {

			flowState, terr := models.NewFlowStateWithUserID(models.Invite.String(), params.CodeChallenge, codeChallengeMethod, models.Invite, &(user.ID))
			if terr != nil {
				return terr
			}
			if terr := tx.Create(flowState); terr != nil {
				return terr
			}
		}
		if err := sendInvite(tx, user, mailer, referrer, config.Mailer.OtpLength, flowType); err != nil {
			return internalServerError("Error inviting user").WithInternalError(err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if isPKCEFlow(flowType) {
		return sendJSON(w, http.StatusOK, map[string]interface{}{})
	}

	return sendJSON(w, http.StatusOK, user)
}
