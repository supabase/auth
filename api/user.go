package api

import (
	"encoding/json"
	"net/http"

	"github.com/netlify/gotrue/api/sms_provider"
	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/observability"
	"github.com/netlify/gotrue/storage"
)

// UserUpdateParams parameters for updating a user
type UserUpdateParams struct {
	Email    string                 `json:"email"`
	Password *string                `json:"password"`
	Nonce    string                 `json:"nonce"`
	Data     map[string]interface{} `json:"data"`
	AppData  map[string]interface{} `json:"app_metadata,omitempty"`
	Phone    string                 `json:"phone"`
}

// UserGet returns a user
func (a *API) UserGet(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	claims := getClaims(ctx)
	if claims == nil {
		return badRequestError("Could not read claims")
	}

	aud := a.requestAud(ctx, r)
	if aud != claims.Audience {
		return badRequestError("Token audience doesn't match request audience")
	}

	user := getUser(ctx)
	return sendJSON(w, http.StatusOK, user)
}

// UserUpdate updates fields on a user
func (a *API) UserUpdate(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	config := a.config

	params := &UserUpdateParams{}

	body, err := getBodyBytes(r)
	if err != nil {
		return badRequestError("Could not read body").WithInternalError(err)
	}

	if err := json.Unmarshal(body, params); err != nil {
		return badRequestError("Could not read User Update params: %v", err)
	}

	user := getUser(ctx)
	session := getSession(ctx)
	log := observability.GetLogEntry(r)
	log.Debugf("Checking params for token %v", params)

	err = db.Transaction(func(tx *storage.Connection) error {
		var terr error
		if params.Password != nil {
			if len(*params.Password) < config.PasswordMinLength {
				return invalidPasswordLengthError(config)
			}

			isPasswordUpdated := false
			if !config.Security.UpdatePasswordRequireReauthentication {
				if terr = user.UpdatePassword(tx, *params.Password); terr != nil {
					return internalServerError("Error during password storage").WithInternalError(terr)
				}
				isPasswordUpdated = true
			} else if params.Nonce == "" {
				return unauthorizedError("Password update requires reauthentication.")
			} else {
				if terr = a.verifyReauthentication(params.Nonce, tx, config, user); terr != nil {
					return terr
				}
				if terr = user.UpdatePassword(tx, *params.Password); terr != nil {
					return internalServerError("Error during password storage").WithInternalError(terr)
				}
				isPasswordUpdated = true
			}

			if isPasswordUpdated {
				if terr := models.NewAuditLogEntry(r, tx, user, models.UserUpdatePasswordAction, "", nil); terr != nil {
					return terr
				}
				if session != nil {
					if terr = models.LogoutAllExceptMe(tx, session.ID, user.ID); terr != nil {
						return terr
					}
				} else {
					// logout all sessions if session id is missing
					if terr = models.Logout(tx, user.ID); terr != nil {
						return terr
					}
				}
			}
		}

		if params.Data != nil {
			if terr = user.UpdateUserMetaData(tx, params.Data); terr != nil {
				return internalServerError("Error updating user").WithInternalError(terr)
			}
		}

		if params.AppData != nil {
			if !a.isAdmin(ctx, user, config.JWT.Aud) {
				return unauthorizedError("Updating app_metadata requires admin privileges")
			}

			if terr = user.UpdateAppMetaData(tx, params.AppData); terr != nil {
				return internalServerError("Error updating user").WithInternalError(terr)
			}
		}

		if params.Email != "" && params.Email != user.GetEmail() {
			params.Email, terr = a.validateEmail(ctx, params.Email)
			if terr != nil {
				return terr
			}

			var exists bool
			if exists, terr = models.IsDuplicatedEmail(tx, params.Email, user.Aud); terr != nil {
				return internalServerError("Database error checking email").WithInternalError(terr)
			} else if exists {
				return unprocessableEntityError(DuplicateEmailMsg)
			}

			mailer := a.Mailer(ctx)
			referrer := a.getReferrer(r)
			if terr = a.sendEmailChange(tx, config, user, mailer, params.Email, referrer, config.Mailer.OtpLength); terr != nil {
				return internalServerError("Error sending change email").WithInternalError(terr)
			}
		}

		if params.Phone != "" && params.Phone != user.GetPhone() {
			params.Phone, err = a.validatePhone(params.Phone)
			if err != nil {
				return err
			}
			var exists bool
			if exists, terr = models.IsDuplicatedPhone(tx, params.Phone, user.Aud); terr != nil {
				return internalServerError("Database error checking phone").WithInternalError(terr)
			} else if exists {
				return unprocessableEntityError(DuplicatePhoneMsg)
			}
			if config.Sms.Autoconfirm {
				return user.UpdatePhone(tx, params.Phone)
			} else {
				smsProvider, terr := sms_provider.GetSmsProvider(*config)
				if terr != nil {
					return badRequestError("Error sending sms: %v", terr)
				}
				if terr := a.sendPhoneConfirmation(ctx, tx, user, params.Phone, phoneChangeVerification, smsProvider); terr != nil {
					return internalServerError("Error sending phone change otp").WithInternalError(terr)
				}
			}
		}

		if terr = models.NewAuditLogEntry(r, tx, user, models.UserModifiedAction, "", nil); terr != nil {
			return internalServerError("Error recording audit log entry").WithInternalError(terr)
		}

		return nil
	})
	if err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, user)
}
