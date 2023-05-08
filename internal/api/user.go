package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/fatih/structs"
	"github.com/supabase/gotrue/internal/api/provider"
	"github.com/supabase/gotrue/internal/api/sms_provider"
	"github.com/supabase/gotrue/internal/models"
	"github.com/supabase/gotrue/internal/observability"
	"github.com/supabase/gotrue/internal/storage"
)

// UserUpdateParams parameters for updating a user
type UserUpdateParams struct {
	Email               string                 `json:"email"`
	Password            *string                `json:"password"`
	Nonce               string                 `json:"nonce"`
	Data                map[string]interface{} `json:"data"`
	AppData             map[string]interface{} `json:"app_metadata,omitempty"`
	Phone               string                 `json:"phone"`
	Channel             string                 `json:"channel"`
	CodeChallenge       string                 `json:"code_challenge"`
	CodeChallengeMethod string                 `json:"code_challenge_method"`
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
	aud := a.requestAud(ctx, r)

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

	if params.Email != "" && params.Email != user.GetEmail() {
		params.Email, err = validateEmail(params.Email)
		if err != nil {
			return err
		}
		var duplicateUser *models.User
		if duplicateUser, err = models.IsDuplicatedEmail(a.db, params.Email, aud, user); err != nil {
			return internalServerError("Database error checking email").WithInternalError(err)
		} else if duplicateUser != nil {
			return unprocessableEntityError(DuplicateEmailMsg)
		}
	}
	if params.Phone != "" && params.Channel == "" {
		params.Channel = sms_provider.SMSProvider
	}
	if params.Phone != "" && !sms_provider.IsValidMessageChannel(params.Channel, config.Sms.Provider) {
		return badRequestError(InvalidChannelError)
	}

	if params.Phone != "" && params.Phone != user.GetPhone() {
		params.Phone, err = validatePhone(params.Phone)
		if err != nil {
			return err
		}
		var exists bool
		if exists, err = models.IsDuplicatedPhone(a.db, params.Phone, aud); err != nil {
			return internalServerError("Database error checking phone").WithInternalError(err)
		} else if exists {
			return unprocessableEntityError(DuplicatePhoneMsg)
		}
	}

	if user.IsSSOUser {
		if (params.Password != nil && *params.Password != "") || params.Email != "" || params.Phone != "" || params.Nonce != "" {
			return unprocessableEntityError("Updating email, phone, password of a SSO account only possible via SSO")
		}
	}

	err = db.Transaction(func(tx *storage.Connection) error {
		var terr error
		if params.Password != nil {
			if len(*params.Password) < config.PasswordMinLength {
				return invalidPasswordLengthError(config.PasswordMinLength)
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

		var identities []models.Identity
		if params.Email != "" && params.Email != user.GetEmail() {
			if user.GetEmail() == "" {
				// if the user doesn't have an existing email
				// then updating the user's email should create a new email identity
				identity, terr := a.createNewIdentity(tx, user, "email", structs.Map(provider.Claims{
					Subject: user.ID.String(),
					Email:   params.Email,
				}))
				if terr != nil {
					return terr
				}
				identities = append(identities, *identity)
			}
			mailer := a.Mailer(ctx)
			referrer := a.getReferrer(r)
			flowType := getFlowFromChallenge(params.CodeChallenge)
			if isPKCEFlow(flowType) {
				codeChallengeMethod, terr := models.ParseCodeChallengeMethod(params.CodeChallengeMethod)
				if terr != nil {
					return terr
				}
				if terr := models.NewFlowStateWithUserID(tx, models.EmailChange.String(), params.CodeChallenge, codeChallengeMethod, models.EmailChange, &user.ID); terr != nil {
					return terr
				}
			}
			externalURL := getExternalHost(ctx)
			if terr = a.sendEmailChange(tx, config, user, mailer, params.Email, referrer, externalURL, config.Mailer.OtpLength, flowType); terr != nil {
				if errors.Is(terr, MaxFrequencyLimitError) {
					return tooManyRequestsError("For security purposes, you can only request this once every 60 seconds")
				}
				return internalServerError("Error sending change email").WithInternalError(terr)
			}
		}

		if params.Phone != "" && params.Phone != user.GetPhone() {
			if user.GetPhone() == "" {
				// if the user doesn't have an existing phone
				// then updating the user's phone should create a new phone identity
				identity, terr := a.createNewIdentity(tx, user, "phone", structs.Map(provider.Claims{
					Subject: user.ID.String(),
					Phone:   params.Phone,
				}))
				if terr != nil {
					return terr
				}
				identities = append(identities, *identity)
			}
			if config.Sms.Autoconfirm {
				return user.UpdatePhone(tx, params.Phone)
			} else {
				smsProvider, terr := sms_provider.GetSmsProvider(*config)
				if terr != nil {
					return badRequestError("Error sending sms: %v", terr)
				}
				if terr := a.sendPhoneConfirmation(ctx, tx, user, params.Phone, phoneChangeVerification, smsProvider, params.Channel); terr != nil {
					return internalServerError("Error sending phone change otp").WithInternalError(terr)
				}
			}
		}
		user.Identities = append(user.Identities, identities...)

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
