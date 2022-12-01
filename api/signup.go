package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/fatih/structs"
	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/api/provider"
	"github.com/netlify/gotrue/api/sms_provider"
	"github.com/netlify/gotrue/metering"
	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
	"github.com/pkg/errors"
)

// SignupParams are the parameters the Signup endpoint accepts
type SignupParams struct {
	Email    string                 `json:"email"`
	Phone    string                 `json:"phone"`
	Password string                 `json:"password"`
	Data     map[string]interface{} `json:"data"`
	Provider string                 `json:"-"`
	Aud      string                 `json:"-"`
}

// Signup is the endpoint for registering a new user
func (a *API) Signup(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	config := a.config
	db := a.db.WithContext(ctx)

	if config.DisableSignup {
		return forbiddenError("Signups not allowed for this instance")
	}

	params := &SignupParams{}

	body, err := getBodyBytes(r)
	if err != nil {
		return badRequestError("Could not read body").WithInternalError(err)
	}

	if err := json.Unmarshal(body, params); err != nil {
		return badRequestError("Could not read Signup params: %v", err)
	}

	if params.Password == "" {
		return unprocessableEntityError("Signup requires a valid password")
	}
	if len(params.Password) < config.PasswordMinLength {
		return unprocessableEntityError(fmt.Sprintf("Password should be at least %d characters", config.PasswordMinLength))
	}
	if params.Email != "" && params.Phone != "" {
		return unprocessableEntityError("Only an email address or phone number should be provided on signup.")
	}
	if params.Email != "" {
		params.Provider = "email"
	} else if params.Phone != "" {
		params.Provider = "phone"
	}
	if params.Data == nil {
		params.Data = make(map[string]interface{})
	}

	var user *models.User
	var grantParams models.GrantParams
	params.Aud = a.requestAud(ctx, r)

	switch params.Provider {
	case "email":
		if !config.External.Email.Enabled {
			return badRequestError("Email signups are disabled")
		}
		params.Email, err = a.validateEmail(ctx, params.Email)
		if err != nil {
			return err
		}
		user, err = models.IsDuplicatedEmail(db, params.Email, params.Aud)
	case "phone":
		if !config.External.Phone.Enabled {
			return badRequestError("Phone signups are disabled")
		}
		params.Phone, err = a.validatePhone(params.Phone)
		if err != nil {
			return err
		}
		user, err = models.FindUserByPhoneAndAudience(db, params.Phone, params.Aud)
	default:
		return invalidSignupError(config)
	}

	if err != nil && !models.IsNotFoundError(err) {
		return internalServerError("Database error finding user").WithInternalError(err)
	}

	err = db.Transaction(func(tx *storage.Connection) error {
		var terr error
		if user != nil {
			if (params.Provider == "email" && user.IsConfirmed()) || (params.Provider == "phone" && user.IsPhoneConfirmed()) {
				return UserExistsError
			}

			// do not update the user because we can't be sure of their claimed identity
		} else {
			user, terr = a.signupNewUser(ctx, tx, params, false /* <- isSSOUser */)
			if terr != nil {
				return terr
			}
			identity, terr := a.createNewIdentity(tx, user, params.Provider, structs.Map(provider.Claims{
				Subject: user.ID.String(),
				Email:   user.GetEmail(),
			}))
			if terr != nil {
				return terr
			}
			user.Identities = []models.Identity{*identity}
		}

		if params.Provider == "email" && !user.IsConfirmed() {
			if config.Mailer.Autoconfirm {
				if terr = models.NewAuditLogEntry(r, tx, user, models.UserSignedUpAction, "", map[string]interface{}{
					"provider": params.Provider,
				}); terr != nil {
					return terr
				}
				if terr = triggerEventHooks(ctx, tx, SignupEvent, user, config); terr != nil {
					return terr
				}
				if terr = user.Confirm(tx); terr != nil {
					return internalServerError("Database error updating user").WithInternalError(terr)
				}
			} else {
				mailer := a.Mailer(ctx)
				referrer := a.getReferrer(r)
				if terr = models.NewAuditLogEntry(r, tx, user, models.UserConfirmationRequestedAction, "", map[string]interface{}{
					"provider": params.Provider,
				}); terr != nil {
					return terr
				}
				if terr = sendConfirmation(tx, user, mailer, config.SMTP.MaxFrequency, referrer, config.Mailer.OtpLength); terr != nil {
					if errors.Is(terr, MaxFrequencyLimitError) {
						now := time.Now()
						left := user.ConfirmationSentAt.Add(config.SMTP.MaxFrequency).Sub(now) / time.Second
						return tooManyRequestsError(fmt.Sprintf("For security purposes, you can only request this after %d seconds.", left))
					}
					return internalServerError("Error sending confirmation mail").WithInternalError(terr)
				}
			}
		} else if params.Provider == "phone" && !user.IsPhoneConfirmed() {
			if config.Sms.Autoconfirm {
				if terr = models.NewAuditLogEntry(r, tx, user, models.UserSignedUpAction, "", map[string]interface{}{
					"provider": params.Provider,
				}); terr != nil {
					return terr
				}
				if terr = triggerEventHooks(ctx, tx, SignupEvent, user, config); terr != nil {
					return terr
				}
				if terr = user.ConfirmPhone(tx); terr != nil {
					return internalServerError("Database error updating user").WithInternalError(terr)
				}
			} else {
				if terr = models.NewAuditLogEntry(r, tx, user, models.UserConfirmationRequestedAction, "", map[string]interface{}{
					"provider": params.Provider,
				}); terr != nil {
					return terr
				}
				smsProvider, terr := sms_provider.GetSmsProvider(*config)
				if terr != nil {
					return badRequestError("Error sending confirmation sms: %v", terr)
				}
				if terr = a.sendPhoneConfirmation(ctx, tx, user, params.Phone, phoneConfirmationOtp, smsProvider); terr != nil {
					return badRequestError("Error sending confirmation sms: %v", terr)
				}
			}
		}

		return nil
	})

	if err != nil {
		if errors.Is(err, MaxFrequencyLimitError) {
			return tooManyRequestsError("For security purposes, you can only request this once every minute")
		}
		if errors.Is(err, UserExistsError) {
			err = db.Transaction(func(tx *storage.Connection) error {
				if terr := models.NewAuditLogEntry(r, tx, user, models.UserRepeatedSignUpAction, "", map[string]interface{}{
					"provider": params.Provider,
				}); terr != nil {
					return terr
				}
				return nil
			})
			if err != nil {
				return err
			}
			if config.Mailer.Autoconfirm || config.Sms.Autoconfirm {
				return badRequestError("User already registered")
			}
			sanitizedUser, err := sanitizeUser(user, params)
			if err != nil {
				return err
			}
			return sendJSON(w, http.StatusOK, sanitizedUser)
		}
		return err
	}

	// handles case where Mailer.Autoconfirm is true or Phone.Autoconfirm is true
	if user.IsConfirmed() || user.IsPhoneConfirmed() {
		var token *AccessTokenResponse
		err = db.Transaction(func(tx *storage.Connection) error {
			var terr error
			if terr = models.NewAuditLogEntry(r, tx, user, models.LoginAction, "", map[string]interface{}{
				"provider": params.Provider,
			}); terr != nil {
				return terr
			}
			if terr = triggerEventHooks(ctx, tx, LoginEvent, user, config); terr != nil {
				return terr
			}
			token, terr = a.issueRefreshToken(ctx, tx, user, models.PasswordGrant, grantParams)

			if terr != nil {
				return terr
			}

			if terr = a.setCookieTokens(config, token, false, w); terr != nil {
				return internalServerError("Failed to set JWT cookie. %s", terr)
			}
			return nil
		})
		if err != nil {
			return err
		}
		metering.RecordLogin("password", user.ID)
		return sendJSON(w, http.StatusOK, token)
	}

	return sendJSON(w, http.StatusOK, user)
}

// sanitizeUser removes all user sensitive information from the user object
// Should be used whenever we want to prevent information about whether a user is registered or not from leaking
func sanitizeUser(u *models.User, params *SignupParams) (*models.User, error) {
	var err error
	now := time.Now()

	u.ID, err = uuid.NewV4()
	if err != nil {
		return nil, errors.Wrap(err, "Error generating unique id")
	}
	u.CreatedAt, u.UpdatedAt, u.ConfirmationSentAt = now, now, &now
	u.LastSignInAt, u.ConfirmedAt, u.EmailConfirmedAt, u.PhoneConfirmedAt = nil, nil, nil, nil
	u.Identities = make([]models.Identity, 0)
	u.UserMetaData = params.Data
	u.Aud = params.Aud

	// sanitize app_metadata
	u.AppMetaData = map[string]interface{}{
		"provider":  params.Provider,
		"providers": []string{params.Provider},
	}

	// sanitize param fields
	switch params.Provider {
	case "email":
		u.Phone = ""
	case "phone":
		u.Email = ""
	default:
		u.Phone, u.Email = "", ""
	}

	return u, nil
}

func (a *API) signupNewUser(ctx context.Context, conn *storage.Connection, params *SignupParams, isSSOUser bool) (*models.User, error) {
	config := a.config

	var user *models.User
	var err error
	switch params.Provider {
	case "email":
		user, err = models.NewUser("", params.Email, params.Password, params.Aud, params.Data)
	case "phone":
		user, err = models.NewUser(params.Phone, "", params.Password, params.Aud, params.Data)
	default:
		// handles external provider case
		user, err = models.NewUser("", params.Email, params.Password, params.Aud, params.Data)
	}

	user.IsSSOUser = isSSOUser

	if err != nil {
		return nil, internalServerError("Database error creating user").WithInternalError(err)
	}
	if user.AppMetaData == nil {
		user.AppMetaData = make(map[string]interface{})
	}

	user.Identities = make([]models.Identity, 0)

	// TODO: Deprecate "provider" field
	user.AppMetaData["provider"] = params.Provider

	user.AppMetaData["providers"] = []string{params.Provider}
	if params.Password == "" {
		user.EncryptedPassword = ""
	}

	err = conn.Transaction(func(tx *storage.Connection) error {
		var terr error
		if terr = tx.Create(user); terr != nil {
			return internalServerError("Database error saving new user").WithInternalError(terr)
		}
		if terr = user.SetRole(tx, config.JWT.DefaultGroupName); terr != nil {
			return internalServerError("Database error updating user").WithInternalError(terr)
		}
		if terr = triggerEventHooks(ctx, tx, ValidateEvent, user, config); terr != nil {
			return terr
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// sometimes there may be triggers in the database that will modify the
	// user data as it is being inserted. thus we load the user object
	// again to fetch those changes.
	err = conn.Eager().Load(user)
	if err != nil {
		return nil, internalServerError("Database error loading user after sign-up").WithInternalError(err)
	}

	return user, nil
}
