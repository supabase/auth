package api

import (
	"net/http"

	"github.com/fatih/structs"
	"github.com/supabase/auth/internal/api/provider"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

// InviteParams are the parameters the Signup endpoint accepts
type InviteParams struct {
	Email string                 `json:"email"`
	Data  map[string]interface{} `json:"data"`
}

// Invite is the endpoint for inviting a new user
func (a *API) Invite(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	adminUser := getAdminUser(ctx)
	params := &InviteParams{}
	if err := retrieveRequestParams(r, params); err != nil {
		return err
	}

	var err error
	params.Email, err = validateEmail(params.Email)
	if err != nil {
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
				return unprocessableEntityError(ErrorCodeEmailExists, DuplicateEmailMsg)
			}
		} else {
			signupParams := SignupParams{
				Email:    params.Email,
				Data:     params.Data,
				Aud:      aud,
				Provider: "email",
			}

			// because params above sets no password, this method
			// is not computationally hard so it can be used within
			// a database transaction
			user, err = signupParams.ToUserModel(false /* <- isSSOUser */)
			if err != nil {
				return err
			}

			user, err = a.signupNewUser(tx, user)
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

		if err := a.sendInvite(r, tx, user); err != nil {
			return internalServerError("Error inviting user").WithInternalError(err)
		}
		return nil
	})
	if err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, user)
}
