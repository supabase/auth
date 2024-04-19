package api

import (
	"github.com/supabase/auth/internal/hooks"
	mail "github.com/supabase/auth/internal/mailer"
	"net/http"
	"strings"
	"time"

	"github.com/badoux/checkmail"
	"github.com/fatih/structs"
	"github.com/pkg/errors"
	"github.com/sethvargo/go-password/password"
	"github.com/supabase/auth/internal/api/provider"
	"github.com/supabase/auth/internal/crypto"
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
	mailer := a.Mailer()
	adminUser := getAdminUser(ctx)
	params := &GenerateLinkParams{}
	if err := retrieveRequestParams(r, params); err != nil {
		return err
	}

	var err error
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
			switch params.Type {
			case mail.MagicLinkVerification:
				params.Type = mail.SignupVerification
				params.Password, err = password.Generate(64, 10, 1, false, true)
				if err != nil {
					// password generation must always succeed
					panic(err)
				}
			case mail.RecoveryVerification, mail.EmailChangeCurrentVerification, mail.EmailChangeNewVerification:
				return notFoundError(ErrorCodeUserNotFound, "User with this email not found")
			}
		} else {
			return internalServerError("Database error finding user").WithInternalError(err)
		}
	}

	var url string
	now := time.Now()
	otp, err := crypto.GenerateOtp(config.Mailer.OtpLength)
	if err != nil {
		// OTP generation must always succeed
		panic(err)
	}

	hashedToken := crypto.GenerateTokenHash(params.Email, otp)

	var signupUser *models.User
	if params.Type == mail.SignupVerification && user == nil {
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
		case mail.MagicLinkVerification, mail.RecoveryVerification:
			if terr = models.NewAuditLogEntry(r, tx, user, models.UserRecoveryRequestedAction, "", nil); terr != nil {
				return terr
			}
			user.RecoveryToken = hashedToken
			user.RecoverySentAt = &now
			terr = tx.UpdateOnly(user, "recovery_token", "recovery_sent_at")
			if terr != nil {
				terr = errors.Wrap(terr, "Database error updating user for recovery")
			}
		case mail.InviteVerification:
			if user != nil {
				if user.IsConfirmed() {
					return unprocessableEntityError(ErrorCodeEmailExists, DuplicateEmailMsg)
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

				user, terr = a.signupNewUser(tx, user)
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
			terr = tx.UpdateOnly(user, "confirmation_token", "confirmation_sent_at", "invited_at")
			if terr != nil {
				terr = errors.Wrap(terr, "Database error updating user for invite")
			}
		case mail.SignupVerification:
			if user != nil {
				if user.IsConfirmed() {
					return unprocessableEntityError(ErrorCodeEmailExists, DuplicateEmailMsg)
				}
				if err := user.UpdateUserMetaData(tx, params.Data); err != nil {
					return internalServerError("Database error updating user").WithInternalError(err)
				}
			} else {
				// you should never use SignupParams with
				// password here to generate a new user, use
				// signupUser which is a model generated from
				// SignupParams above
				user, terr = a.signupNewUser(tx, signupUser)
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
			terr = tx.UpdateOnly(user, "confirmation_token", "confirmation_sent_at")
			if terr != nil {
				terr = errors.Wrap(terr, "Database error updating user for confirmation")
			}
		case mail.EmailChangeCurrentVerification, mail.EmailChangeNewVerification:
			if !config.Mailer.SecureEmailChangeEnabled && params.Type == "email_change_current" {
				return badRequestError(ErrorCodeValidationFailed, "Enable secure email change to generate link for current email")
			}
			params.NewEmail, terr = validateEmail(params.NewEmail)
			if terr != nil {
				return terr
			}
			if duplicateUser, terr := models.IsDuplicatedEmail(tx, params.NewEmail, user.Aud, user); terr != nil {
				return internalServerError("Database error checking email").WithInternalError(terr)
			} else if duplicateUser != nil {
				return unprocessableEntityError(ErrorCodeEmailExists, DuplicateEmailMsg)
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
			terr = tx.UpdateOnly(user, "email_change_token_current", "email_change_token_new", "email_change", "email_change_sent_at", "email_change_confirm_status")
			if terr != nil {
				terr = errors.Wrap(terr, "Database error updating user for email change")
			}
		default:
			return badRequestError(ErrorCodeValidationFailed, "Invalid email action link type requested: %v", params.Type)
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

func (a *API) sendConfirmation(r *http.Request, tx *storage.Connection, u *models.User, flowType models.FlowType) error {
	config := a.config
	maxFrequency := config.SMTP.MaxFrequency
	otpLength := config.Mailer.OtpLength

	var err error
	if err := validateSentWithinFrequencyLimit(u.ConfirmationSentAt, maxFrequency); err != nil {
		return err
	}
	oldToken := u.ConfirmationToken
	otp, err := crypto.GenerateOtp(otpLength)
	if err != nil {
		// OTP generation must succeeed
		panic(err)
	}
	token := crypto.GenerateTokenHash(u.GetEmail(), otp)
	u.ConfirmationToken = addFlowPrefixToToken(token, flowType)
	now := time.Now()
	err = a.sendEmail(r, tx, u, mail.SignupVerification, otp, "", u.ConfirmationToken)
	if err != nil {
		u.ConfirmationToken = oldToken
		return errors.Wrap(err, "Error sending confirmation email")
	}
	u.ConfirmationSentAt = &now
	err = tx.UpdateOnly(u, "confirmation_token", "confirmation_sent_at")
	if err != nil {
		return errors.Wrap(err, "Database error updating user for confirmation")
	}

	return nil
}

func (a *API) sendInvite(r *http.Request, tx *storage.Connection, u *models.User) error {
	config := a.config
	otpLength := config.Mailer.OtpLength
	var err error
	oldToken := u.ConfirmationToken
	otp, err := crypto.GenerateOtp(otpLength)
	if err != nil {
		// OTP generation must succeed
		panic(err)
	}
	u.ConfirmationToken = crypto.GenerateTokenHash(u.GetEmail(), otp)
	now := time.Now()
	err = a.sendEmail(r, tx, u, mail.InviteVerification, otp, "", u.ConfirmationToken)
	if err != nil {
		u.ConfirmationToken = oldToken
		return errors.Wrap(err, "Error sending invite email")
	}
	u.InvitedAt = &now
	u.ConfirmationSentAt = &now
	err = tx.UpdateOnly(u, "confirmation_token", "confirmation_sent_at", "invited_at")
	if err != nil {
		return errors.Wrap(err, "Database error updating user for invite")
	}

	return nil
}

func (a *API) sendPasswordRecovery(r *http.Request, tx *storage.Connection, u *models.User, flowType models.FlowType) error {
	config := a.config
	maxFrequency := config.SMTP.MaxFrequency
	otpLength := config.Mailer.OtpLength
	var err error
	if err := validateSentWithinFrequencyLimit(u.RecoverySentAt, maxFrequency); err != nil {
		return err
	}

	oldToken := u.RecoveryToken
	otp, err := crypto.GenerateOtp(otpLength)
	if err != nil {
		// OTP generation must succeed
		panic(err)
	}
	token := crypto.GenerateTokenHash(u.GetEmail(), otp)
	u.RecoveryToken = addFlowPrefixToToken(token, flowType)
	now := time.Now()
	err = a.sendEmail(r, tx, u, mail.RecoveryVerification, otp, "", u.RecoveryToken)
	if err != nil {
		u.RecoveryToken = oldToken
		return errors.Wrap(err, "Error sending recovery email")
	}
	u.RecoverySentAt = &now
	err = tx.UpdateOnly(u, "recovery_token", "recovery_sent_at")
	if err != nil {
		return errors.Wrap(err, "Database error updating user for recovery")
	}

	return nil
}

func (a *API) sendReauthenticationOtp(r *http.Request, tx *storage.Connection, u *models.User) error {
	config := a.config
	maxFrequency := config.SMTP.MaxFrequency
	otpLength := config.Mailer.OtpLength
	var err error

	if err := validateSentWithinFrequencyLimit(u.ReauthenticationSentAt, maxFrequency); err != nil {
		return err
	}

	oldToken := u.ReauthenticationToken
	otp, err := crypto.GenerateOtp(otpLength)
	if err != nil {
		// OTP generation must succeed
		panic(err)
	}
	u.ReauthenticationToken = crypto.GenerateTokenHash(u.GetEmail(), otp)
	now := time.Now()
	err = a.sendEmail(r, tx, u, mail.ReauthenticationVerification, otp, "", u.ReauthenticationToken)
	if err != nil {
		u.ReauthenticationToken = oldToken
		return errors.Wrap(err, "Error sending reauthentication email")
	}
	u.ReauthenticationSentAt = &now
	err = tx.UpdateOnly(u, "reauthentication_token", "reauthentication_sent_at")
	if err != nil {
		return errors.Wrap(err, "Database error updating user for reauthentication")
	}

	return nil
}

func (a *API) sendMagicLink(r *http.Request, tx *storage.Connection, u *models.User, flowType models.FlowType) error {
	config := a.config
	otpLength := config.Mailer.OtpLength
	maxFrequency := config.SMTP.MaxFrequency
	var err error
	// since Magic Link is just a recovery with a different template and behaviour
	// around new users we will reuse the recovery db timer to prevent potential abuse
	if err := validateSentWithinFrequencyLimit(u.RecoverySentAt, maxFrequency); err != nil {
		return err
	}

	oldToken := u.RecoveryToken
	otp, err := crypto.GenerateOtp(otpLength)
	if err != nil {
		// OTP generation must succeed
		panic(err)
	}
	token := crypto.GenerateTokenHash(u.GetEmail(), otp)
	u.RecoveryToken = addFlowPrefixToToken(token, flowType)

	now := time.Now()
	err = a.sendEmail(r, tx, u, mail.MagicLinkVerification, otp, "", u.RecoveryToken)
	if err != nil {
		u.RecoveryToken = oldToken
		return errors.Wrap(err, "Error sending magic link email")
	}
	u.RecoverySentAt = &now
	err = tx.UpdateOnly(u, "recovery_token", "recovery_sent_at")
	if err != nil {
		return errors.Wrap(err, "Database error updating user for recovery")
	}

	return nil
}

// sendEmailChange sends out an email change token to the new email.
func (a *API) sendEmailChange(r *http.Request, tx *storage.Connection, u *models.User, email string, flowType models.FlowType) error {
	config := a.config
	otpLength := config.Mailer.OtpLength
	var err error
	if err := validateSentWithinFrequencyLimit(u.EmailChangeSentAt, config.SMTP.MaxFrequency); err != nil {
		return err
	}

	otpNew, err := crypto.GenerateOtp(otpLength)
	if err != nil {
		// OTP generation must succeed
		panic(err)
	}
	u.EmailChange = email
	token := crypto.GenerateTokenHash(u.EmailChange, otpNew)
	u.EmailChangeTokenNew = addFlowPrefixToToken(token, flowType)

	otpCurrent := ""
	if config.Mailer.SecureEmailChangeEnabled && u.GetEmail() != "" {
		otpCurrent, err = crypto.GenerateOtp(otpLength)
		if err != nil {
			// OTP generation must succeed
			panic(err)
		}
		currentToken := crypto.GenerateTokenHash(u.GetEmail(), otpCurrent)
		u.EmailChangeTokenCurrent = addFlowPrefixToToken(currentToken, flowType)
	}

	u.EmailChangeConfirmStatus = zeroConfirmation
	now := time.Now()
	err = a.sendEmail(r, tx, u, mail.EmailChangeVerification, otpCurrent, otpNew, u.EmailChangeTokenNew)
	if err != nil {
		return err
	}

	u.EmailChangeSentAt = &now
	err = tx.UpdateOnly(
		u,
		"email_change_token_current",
		"email_change_token_new",
		"email_change",
		"email_change_sent_at",
		"email_change_confirm_status",
	)

	if err != nil {
		return errors.Wrap(err, "Database error updating user for email change")
	}

	return nil
}

func validateEmail(email string) (string, error) {
	if email == "" {
		return "", badRequestError(ErrorCodeValidationFailed, "An email address is required")
	}
	if err := checkmail.ValidateFormat(email); err != nil {
		return "", badRequestError(ErrorCodeValidationFailed, "Unable to validate email address: "+err.Error())
	}
	return strings.ToLower(email), nil
}

func validateSentWithinFrequencyLimit(sentAt *time.Time, frequency time.Duration) error {
	if sentAt != nil && sentAt.Add(frequency).After(time.Now()) {
		return MaxFrequencyLimitError
	}
	return nil
}

func (a *API) sendEmail(r *http.Request, tx *storage.Connection, u *models.User, emailActionType, otp, otpNew, tokenHashWithPrefix string) error {
	mailer := a.Mailer()
	ctx := r.Context()
	config := a.config
	referrerURL := utilities.GetReferrer(r, config)
	externalURL := getExternalHost(ctx)
	if config.Hook.SendEmail.Enabled {
		emailData := mail.EmailData{
			Token:           otp,
			EmailActionType: emailActionType,
			RedirectTo:      referrerURL,
			SiteURL:         externalURL.String(),
			TokenHash:       tokenHashWithPrefix,
		}
		if emailActionType == mail.EmailChangeVerification && config.Mailer.SecureEmailChangeEnabled && u.GetEmail() != "" {
			emailData.TokenNew = otpNew
			emailData.TokenHashNew = u.EmailChangeTokenCurrent
		}
		input := hooks.SendEmailInput{
			User:      u,
			EmailData: emailData,
		}
		output := hooks.SendEmailOutput{}
		return a.invokeHook(tx, r, &input, &output, a.config.Hook.SendEmail.URI)
	}

	switch emailActionType {
	case mail.SignupVerification:
		return mailer.ConfirmationMail(r, u, otp, referrerURL, externalURL)
	case mail.MagicLinkVerification:
		return mailer.MagicLinkMail(r, u, otp, referrerURL, externalURL)
	case mail.ReauthenticationVerification:
		return mailer.ReauthenticateMail(r, u, otp)
	case mail.RecoveryVerification:
		return mailer.RecoveryMail(r, u, otp, referrerURL, externalURL)
	case mail.InviteVerification:
		return mailer.InviteMail(r, u, otp, referrerURL, externalURL)
	case mail.EmailChangeVerification:
		return mailer.EmailChangeMail(r, u, otpNew, otp, referrerURL, externalURL)
	default:
		return errors.New("invalid email action type")
	}
}
