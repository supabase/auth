package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/fatih/structs"
	"github.com/gofrs/uuid"
	"github.com/supabase/gotrue/internal/api/provider"
	"github.com/supabase/gotrue/internal/api/sms_provider"
	"github.com/supabase/gotrue/internal/conf"
	"github.com/supabase/gotrue/internal/models"
	"github.com/supabase/gotrue/internal/observability"
	"github.com/supabase/gotrue/internal/storage"
	"github.com/supabase/gotrue/internal/utilities"
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

func (p *UserUpdateParams) Validate(tx *storage.Connection, user *models.User, aud string, config *conf.GlobalConfiguration) error {
	var err error
	if p.Email != "" && p.Email != user.GetEmail() {
		p.Email, err = validateEmail(p.Email)
		if err != nil {
			return err
		}
		if duplicateUser, err := models.IsDuplicatedEmail(tx, p.Email, aud, user); err != nil {
			return internalServerError("Database error checking email").WithInternalError(err)
		} else if duplicateUser != nil {
			return unprocessableEntityError(DuplicateEmailMsg)
		}
	}
	if p.Phone != "" {
		if p.Channel == "" {
			p.Channel = sms_provider.SMSProvider
		}
		if !sms_provider.IsValidMessageChannel(p.Channel, config.Sms.Provider) {
			return badRequestError(InvalidChannelError)
		}
		if p.Phone != user.GetPhone() {
			if p.Phone, err = validatePhone(p.Phone); err != nil {
				return err
			}
			if exists, err := models.IsDuplicatedPhone(tx, p.Phone, aud); err != nil {
				return internalServerError("Database error checking phone").WithInternalError(err)
			} else if exists {
				return unprocessableEntityError(DuplicatePhoneMsg)
			}
		}
	}
	if user.IsSSOUser {
		if (p.Password != nil && *p.Password != "") || p.Email != "" || p.Phone != "" || p.Nonce != "" {
			return unprocessableEntityError("Updating email, phone, password of a SSO account only possible via SSO")
		}
	}
	if p.Password != nil {
		password := *p.Password

		if len(password) < config.PasswordMinLength {
			return invalidPasswordLengthError(config.PasswordMinLength)
		}

		if user.EncryptedPassword != "" && user.Authenticate(password) {
			return unprocessableEntityError("New password should be different from the old password.")
		}
	}
	if p.AppData != nil {
		if !isAdmin(user, config) {
			return unauthorizedError("Updating app_metadata requires admin privileges")
		}
	}
	return nil
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

	if err := params.Validate(a.db, user, aud, config); err != nil {
		return err
	}

	err = db.Transaction(func(tx *storage.Connection) error {
		var terr error
		if params.Password != nil {
			if config.Security.UpdatePasswordRequireReauthentication {
				now := time.Now()
				// we require reauthentication if the user hasn't signed in recently in the current session
				if session == nil || now.After(session.CreatedAt.Add(24*time.Hour)) {
					if len(params.Nonce) == 0 {
						return badRequestError("Password update requires reauthentication")
					}
					if terr = a.verifyReauthentication(params.Nonce, tx, config, user); terr != nil {
						return terr
					}
				}
			}

			var sessionID *uuid.UUID
			if session != nil {
				sessionID = &session.ID
			}

			if terr = user.UpdatePassword(tx, *params.Password, sessionID); terr != nil {
				return internalServerError("Error during password storage").WithInternalError(terr)
			}
			if terr := models.NewAuditLogEntry(r, tx, user, models.UserUpdatePasswordAction, "", nil); terr != nil {
				return terr
			}
		}

		if params.Data != nil {
			if terr = user.UpdateUserMetaData(tx, params.Data); terr != nil {
				return internalServerError("Error updating user").WithInternalError(terr)
			}
		}

		if params.AppData != nil {
			if terr = user.UpdateAppMetaData(tx, params.AppData); terr != nil {
				return internalServerError("Error updating user").WithInternalError(terr)
			}
		}

		var identities []models.Identity
		if params.Email != "" && params.Email != user.GetEmail() {
			identity, terr := models.FindIdentityByIdAndProvider(tx, user.ID.String(), "email")
			if terr != nil {
				if !models.IsNotFoundError(terr) {
					return terr
				}
				// updating the user's email should create a new email identity since the user doesn't have one
				identity, terr = a.createNewIdentity(tx, user, "email", structs.Map(provider.Claims{
					Subject: user.ID.String(),
					Email:   params.Email,
				}))
				if terr != nil {
					return terr
				}
			} else {
				if terr := identity.UpdateIdentityData(tx, map[string]interface{}{
					"email": params.Email,
				}); terr != nil {
					return terr
				}
			}
			identities = append(identities, *identity)
			mailer := a.Mailer(ctx)
			referrer := utilities.GetReferrer(r, config)
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
			identity, terr := models.FindIdentityByIdAndProvider(tx, user.ID.String(), "phone")
			if terr != nil {
				if !models.IsNotFoundError(terr) {
					return terr
				}
				// updating the user's phone should create a new phone identity since the user doesn't have one
				identity, terr = a.createNewIdentity(tx, user, "phone", structs.Map(provider.Claims{
					Subject: user.ID.String(),
					Phone:   params.Phone,
				}))
				if terr != nil {
					return terr
				}
			} else {
				if terr := identity.UpdateIdentityData(tx, map[string]interface{}{
					"phone": params.Phone,
				}); terr != nil {
					return terr
				}
			}
			identities = append(identities, *identity)
			if config.Sms.Autoconfirm {
				return user.UpdatePhone(tx, params.Phone)
			} else {
				smsProvider, terr := sms_provider.GetSmsProvider(*config)
				if terr != nil {
					return badRequestError("Error sending sms: %v", terr)
				}
				if _, terr := a.sendPhoneConfirmation(ctx, tx, user, params.Phone, phoneChangeVerification, smsProvider, params.Channel); terr != nil {
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
