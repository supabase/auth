package api

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/badoux/checkmail"
	"github.com/fatih/structs"
	"github.com/pkg/errors"
	"github.com/sethvargo/go-password/password"
	"github.com/supabase/auth/internal/api/provider"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/crypto"
	"github.com/supabase/auth/internal/mailer"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/utilities"
)

var (
	MaxFrequencyLimitError error = errors.New("frequency limit reached")
)

type GenerateLinkParams struct {
	Type       string                 `json:"type"`
	Email      string                 `json:"email"`
	NewEmail   string                 `json:"new_email"`
	Password   string                 `json:"password"`
	Data       map[string]interface{} `json:"data"`
	RedirectTo string                 `json:"redirect_to"`
}

type GenerateLinkResponse struct {
	models.User
	ActionLink       string `json:"action_link"`
	EmailOtp         string `json:"email_otp"`
	HashedToken      string `json:"hashed_token"`
	VerificationType string `json:"verification_type"`
	RedirectTo       string `json:"redirect_to"`
}

func (a *API) adminGenerateLink(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	config := a.config
	mailer := a.Mailer(ctx)
	adminUser := getAdminUser(ctx)
	params := &GenerateLinkParams{}

	body, err := getBodyBytes(r)
	if err != nil {
		return badRequestError("Could not read body").WithInternalError(err)
	}

	if err := json.Unmarshal(body, params); err != nil {
		return badRequestError("Could not parse JSON: %v", err)
	}

	params.Email, err = validateEmail(params.Email)
	if err != nil {
		return err
	}
	referrer := utilities.GetReferrer(r, config)
	if utilities.IsRedirectURLValid(config, params.RedirectTo) {
		referrer = params.RedirectTo
	}

	aud := a.requestAud(ctx, r)
	user, err := models.FindUserByEmailAndAudience(db, params.Email, aud)
	if err != nil {
		if models.IsNotFoundError(err) {
			if params.Type == magicLinkVerification {
				params.Type = signupVerification
				params.Password, err = password.Generate(64, 10, 1, false, true)
				if err != nil {
					return internalServerError("error creating user").WithInternalError(err)
				}
			} else if params.Type == recoveryVerification || params.Type == "email_change_current" || params.Type == "email_change_new" {
				return notFoundError(err.Error())
			}
		} else {
			return internalServerError("Database error finding user").WithInternalError(err)
		}
	}

	var url string
	now := time.Now()
	otp, err := crypto.GenerateOtp(config.Mailer.OtpLength)
	if err != nil {
		return err
	}

	hashedToken := crypto.GenerateTokenHash(params.Email, otp)

	var signupUser *models.User
	if params.Type == signupVerification && user == nil {
		signupParams := &SignupParams{
			Email:    params.Email,
			Password: params.Password,
			Data:     params.Data,
			Provider: "email",
			Aud:      aud,
		}

		if err := a.validateSignupParams(ctx, signupParams); err != nil {
			return err
		}

		signupUser, err = signupParams.ToUserModel(false /* <- isSSOUser */)
		if err != nil {
			return err
		}
	}

	err = db.Transaction(func(tx *storage.Connection) error {
		var terr error
		switch params.Type {
		case magicLinkVerification, recoveryVerification:
			if terr = models.NewAuditLogEntry(r, tx, user, models.UserRecoveryRequestedAction, "", nil); terr != nil {
				return terr
			}
			user.RecoveryToken = hashedToken
			user.RecoverySentAt = &now
			terr = errors.Wrap(tx.UpdateOnly(user, "recovery_token", "recovery_sent_at"), "Database error updating user for recovery")
		case inviteVerification:
			if user != nil {
				if user.IsConfirmed() {
					return unprocessableEntityError(DuplicateEmailMsg)
				}
			} else {
				signupParams := &SignupParams{
					Email:    params.Email,
					Data:     params.Data,
					Provider: "email",
					Aud:      aud,
				}

				// because params above sets no password, this
				// method is not computationally hard so it can
				// be used within a database transaction
				user, terr = signupParams.ToUserModel(false /* <- isSSOUser */)
				if terr != nil {
					return terr
				}

				user, terr = a.signupNewUser(ctx, tx, user)
				if terr != nil {
					return terr
				}
				identity, terr := a.createNewIdentity(tx, user, "email", structs.Map(provider.Claims{
					Subject: user.ID.String(),
					Email:   user.GetEmail(),
				}))
				if terr != nil {
					return terr
				}
				user.Identities = []models.Identity{*identity}
			}
			if terr = models.NewAuditLogEntry(r, tx, adminUser, models.UserInvitedAction, "", map[string]interface{}{
				"user_id":    user.ID,
				"user_email": user.Email,
			}); terr != nil {
				return terr
			}
			user.ConfirmationToken = hashedToken
			user.ConfirmationSentAt = &now
			user.InvitedAt = &now
			terr = errors.Wrap(tx.UpdateOnly(user, "confirmation_token", "confirmation_sent_at", "invited_at"), "Database error updating user for invite")
		case signupVerification:
			if user != nil {
				if user.IsConfirmed() {
					return unprocessableEntityError(DuplicateEmailMsg)
				}
				if err := user.UpdateUserMetaData(tx, params.Data); err != nil {
					return internalServerError("Database error updating user").WithInternalError(err)
				}
			} else {
				// you should never use SignupParams with
				// password here to generate a new user, use
				// signupUser which is a model generated from
				// SignupParams above
				user, terr = a.signupNewUser(ctx, tx, signupUser)
				if terr != nil {
					return terr
				}
				identity, terr := a.createNewIdentity(tx, user, "email", structs.Map(provider.Claims{
					Subject: user.ID.String(),
					Email:   user.GetEmail(),
				}))
				if terr != nil {
					return terr
				}
				user.Identities = []models.Identity{*identity}
			}
			user.ConfirmationToken = hashedToken
			user.ConfirmationSentAt = &now
			terr = errors.Wrap(tx.UpdateOnly(user, "confirmation_token", "confirmation_sent_at"), "Database error updating user for confirmation")
		case "email_change_current", "email_change_new":
			if !config.Mailer.SecureEmailChangeEnabled && params.Type == "email_change_current" {
				return unprocessableEntityError("Enable secure email change to generate link for current email")
			}
			params.NewEmail, terr = validateEmail(params.NewEmail)
			if terr != nil {
				return unprocessableEntityError("The new email address provided is invalid")
			}
			if duplicateUser, terr := models.IsDuplicatedEmail(tx, params.NewEmail, user.Aud, user); terr != nil {
				return internalServerError("Database error checking email").WithInternalError(terr)
			} else if duplicateUser != nil {
				return unprocessableEntityError(DuplicateEmailMsg)
			}
			now := time.Now()
			user.EmailChangeSentAt = &now
			user.EmailChange = params.NewEmail
			user.EmailChangeConfirmStatus = zeroConfirmation
			if params.Type == "email_change_current" {
				user.EmailChangeTokenCurrent = hashedToken
			} else if params.Type == "email_change_new" {
				user.EmailChangeTokenNew = crypto.GenerateTokenHash(params.NewEmail, otp)
			}
			terr = errors.Wrap(tx.UpdateOnly(user, "email_change_token_current", "email_change_token_new", "email_change", "email_change_sent_at", "email_change_confirm_status"), "Database error updating user for email change")
		default:
			return badRequestError("Invalid email action link type requested: %v", params.Type)
		}

		if terr != nil {
			return terr
		}

		externalURL := getExternalHost(ctx)
		url, terr = mailer.GetEmailActionLink(user, params.Type, referrer, externalURL)
		if terr != nil {
			return terr
		}
		return nil
	})

	if err != nil {
		return err
	}

	resp := GenerateLinkResponse{
		User:             *user,
		ActionLink:       url,
		EmailOtp:         otp,
		HashedToken:      hashedToken,
		VerificationType: params.Type,
		RedirectTo:       referrer,
	}

	return sendJSON(w, http.StatusOK, resp)
}

func sendConfirmation(tx *storage.Connection, u *models.User, mailer mailer.Mailer, maxFrequency time.Duration, referrerURL string, externalURL *url.URL, otpLength int, flowType models.FlowType) error {
	var err error
	if u.ConfirmationSentAt != nil && !u.ConfirmationSentAt.Add(maxFrequency).Before(time.Now()) {
		return MaxFrequencyLimitError
	}
	oldToken := u.ConfirmationToken
	otp, err := crypto.GenerateOtp(otpLength)
	if err != nil {
		return err
	}
	token := crypto.GenerateTokenHash(u.GetEmail(), otp)
	u.ConfirmationToken = addFlowPrefixToToken(token, flowType)
	now := time.Now()
	if err := mailer.ConfirmationMail(u, otp, referrerURL, externalURL); err != nil {
		u.ConfirmationToken = oldToken
		return errors.Wrap(err, "Error sending confirmation email")
	}
	u.ConfirmationSentAt = &now
	return errors.Wrap(tx.UpdateOnly(u, "confirmation_token", "confirmation_sent_at"), "Database error updating user for confirmation")
}

func sendInvite(tx *storage.Connection, u *models.User, mailer mailer.Mailer, referrerURL string, externalURL *url.URL, otpLength int) error {
	var err error
	oldToken := u.ConfirmationToken
	otp, err := crypto.GenerateOtp(otpLength)
	if err != nil {
		return err
	}
	u.ConfirmationToken = crypto.GenerateTokenHash(u.GetEmail(), otp)
	now := time.Now()
	if err := mailer.InviteMail(u, otp, referrerURL, externalURL); err != nil {
		u.ConfirmationToken = oldToken
		return errors.Wrap(err, "Error sending invite email")
	}
	u.InvitedAt = &now
	u.ConfirmationSentAt = &now
	return errors.Wrap(tx.UpdateOnly(u, "confirmation_token", "confirmation_sent_at", "invited_at"), "Database error updating user for invite")
}

func (a *API) sendPasswordRecovery(tx *storage.Connection, u *models.User, mailer mailer.Mailer, maxFrequency time.Duration, referrerURL string, externalURL *url.URL, otpLength int, flowType models.FlowType) error {
	var err error
	if u.RecoverySentAt != nil && !u.RecoverySentAt.Add(maxFrequency).Before(time.Now()) {
		return MaxFrequencyLimitError
	}

	oldToken := u.RecoveryToken
	otp, err := crypto.GenerateOtp(otpLength)
	if err != nil {
		return err
	}
	token := crypto.GenerateTokenHash(u.GetEmail(), otp)
	u.RecoveryToken = addFlowPrefixToToken(token, flowType)
	now := time.Now()
	if err := mailer.RecoveryMail(u, otp, referrerURL, externalURL); err != nil {
		u.RecoveryToken = oldToken
		return errors.Wrap(err, "Error sending recovery email")
	}
	u.RecoverySentAt = &now
	return errors.Wrap(tx.UpdateOnly(u, "recovery_token", "recovery_sent_at"), "Database error updating user for recovery")
}

func (a *API) sendReauthenticationOtp(tx *storage.Connection, u *models.User, mailer mailer.Mailer, maxFrequency time.Duration, otpLength int) error {
	var err error
	if u.ReauthenticationSentAt != nil && !u.ReauthenticationSentAt.Add(maxFrequency).Before(time.Now()) {
		return MaxFrequencyLimitError
	}

	oldToken := u.ReauthenticationToken
	otp, err := crypto.GenerateOtp(otpLength)
	if err != nil {
		return err
	}
	u.ReauthenticationToken = crypto.GenerateTokenHash(u.GetEmail(), otp)
	if err != nil {
		return err
	}
	now := time.Now()
	if err := mailer.ReauthenticateMail(u, otp); err != nil {
		u.ReauthenticationToken = oldToken
		return errors.Wrap(err, "Error sending reauthentication email")
	}
	u.ReauthenticationSentAt = &now
	return errors.Wrap(tx.UpdateOnly(u, "reauthentication_token", "reauthentication_sent_at"), "Database error updating user for reauthentication")
}

func (a *API) sendMagicLink(tx *storage.Connection, u *models.User, mailer mailer.Mailer, maxFrequency time.Duration, referrerURL string, externalURL *url.URL, otpLength int, flowType models.FlowType) error {
	var err error
	// since Magic Link is just a recovery with a different template and behaviour
	// around new users we will reuse the recovery db timer to prevent potential abuse
	if u.RecoverySentAt != nil && !u.RecoverySentAt.Add(maxFrequency).Before(time.Now()) {
		return MaxFrequencyLimitError
	}
	oldToken := u.RecoveryToken
	otp, err := crypto.GenerateOtp(otpLength)
	if err != nil {
		return err
	}
	token := crypto.GenerateTokenHash(u.GetEmail(), otp)
	u.RecoveryToken = addFlowPrefixToToken(token, flowType)

	now := time.Now()
	if err := mailer.MagicLinkMail(u, otp, referrerURL, externalURL); err != nil {
		u.RecoveryToken = oldToken
		return errors.Wrap(err, "Error sending magic link email")
	}
	u.RecoverySentAt = &now
	return errors.Wrap(tx.UpdateOnly(u, "recovery_token", "recovery_sent_at"), "Database error updating user for recovery")
}

// sendEmailChange sends out an email change token to the new email.
func (a *API) sendEmailChange(tx *storage.Connection, config *conf.GlobalConfiguration, u *models.User, mailer mailer.Mailer, email, referrerURL string, externalURL *url.URL, otpLength int, flowType models.FlowType) error {
	var err error
	if u.EmailChangeSentAt != nil && !u.EmailChangeSentAt.Add(config.SMTP.MaxFrequency).Before(time.Now()) {
		return MaxFrequencyLimitError
	}
	otpNew, err := crypto.GenerateOtp(otpLength)
	if err != nil {
		return err
	}
	u.EmailChange = email
	token := crypto.GenerateTokenHash(u.EmailChange, otpNew)
	u.EmailChangeTokenNew = addFlowPrefixToToken(token, flowType)

	otpCurrent := ""
	if config.Mailer.SecureEmailChangeEnabled && u.GetEmail() != "" {
		otpCurrent, err = crypto.GenerateOtp(otpLength)
		if err != nil {
			return err
		}
		currentToken := crypto.GenerateTokenHash(u.GetEmail(), otpCurrent)
		u.EmailChangeTokenCurrent = addFlowPrefixToToken(currentToken, flowType)
		if err != nil {
			return err
		}
	}

	u.EmailChangeConfirmStatus = zeroConfirmation
	now := time.Now()
	if err := mailer.EmailChangeMail(u, otpNew, otpCurrent, referrerURL, externalURL); err != nil {
		return err
	}

	u.EmailChangeSentAt = &now
	return errors.Wrap(tx.UpdateOnly(
		u,
		"email_change_token_current",
		"email_change_token_new",
		"email_change",
		"email_change_sent_at",
		"email_change_confirm_status",
	), "Database error updating user for email change")
}

func validateEmail(email string) (string, error) {
	if email == "" {
		return "", unprocessableEntityError("An email address is required")
	}
	if err := checkmail.ValidateFormat(email); err != nil {
		return "", unprocessableEntityError("Unable to validate email address: " + err.Error())
	}
	return strings.ToLower(email), nil
}
