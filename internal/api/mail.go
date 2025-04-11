package api

import (
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/supabase/auth/internal/hooks/v0hooks"
	mail "github.com/supabase/auth/internal/mailer"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/badoux/checkmail"
	"github.com/fatih/structs"
	"github.com/pkg/errors"
	"github.com/sethvargo/go-password/password"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/api/provider"
	"github.com/supabase/auth/internal/crypto"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/utilities"
)

var (
	EmailRateLimitExceeded error = errors.New("email rate limit exceeded")
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
	params.Email, err = a.validateEmail(params.Email)
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
				return apierrors.NewNotFoundError(apierrors.ErrorCodeUserNotFound, "User with this email not found")
			}
		} else {
			return apierrors.NewInternalServerError("Database error finding user").WithInternalError(err)
		}
	}

	var url string
	now := time.Now()
	otp := crypto.GenerateOtp(config.Mailer.OtpLength)

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
				return terr
			}

			terr = models.CreateOneTimeToken(tx, user.ID, user.GetEmail(), user.RecoveryToken, models.RecoveryToken)
			if terr != nil {
				terr = errors.Wrap(terr, "Database error creating recovery token in admin")
				return terr
			}
		case mail.InviteVerification:
			if user != nil {
				if user.IsConfirmed() {
					return apierrors.NewUnprocessableEntityError(apierrors.ErrorCodeEmailExists, DuplicateEmailMsg)
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
				return terr
			}
			terr = models.CreateOneTimeToken(tx, user.ID, user.GetEmail(), user.ConfirmationToken, models.ConfirmationToken)
			if terr != nil {
				terr = errors.Wrap(terr, "Database error creating confirmation token for invite in admin")
				return terr
			}
		case mail.SignupVerification:
			if user != nil {
				if user.IsConfirmed() {
					return apierrors.NewUnprocessableEntityError(apierrors.ErrorCodeEmailExists, DuplicateEmailMsg)
				}
				if err := user.UpdateUserMetaData(tx, params.Data); err != nil {
					return apierrors.NewInternalServerError("Database error updating user").WithInternalError(err)
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
				return terr
			}
			terr = models.CreateOneTimeToken(tx, user.ID, user.GetEmail(), user.ConfirmationToken, models.ConfirmationToken)
			if terr != nil {
				terr = errors.Wrap(terr, "Database error creating confirmation token for signup in admin")
				return terr
			}
		case mail.EmailChangeCurrentVerification, mail.EmailChangeNewVerification:
			if !config.Mailer.SecureEmailChangeEnabled && params.Type == "email_change_current" {
				return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Enable secure email change to generate link for current email")
			}
			params.NewEmail, terr = a.validateEmail(params.NewEmail)
			if terr != nil {
				return terr
			}
			if duplicateUser, terr := models.IsDuplicatedEmail(tx, params.NewEmail, user.Aud, user); terr != nil {
				return apierrors.NewInternalServerError("Database error checking email").WithInternalError(terr)
			} else if duplicateUser != nil {
				return apierrors.NewUnprocessableEntityError(apierrors.ErrorCodeEmailExists, DuplicateEmailMsg)
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
				return terr
			}
			if user.EmailChangeTokenCurrent != "" {
				terr = models.CreateOneTimeToken(tx, user.ID, user.GetEmail(), user.EmailChangeTokenCurrent, models.EmailChangeTokenCurrent)
				if terr != nil {
					terr = errors.Wrap(terr, "Database error creating email change token current in admin")
					return terr
				}
			}
			if user.EmailChangeTokenNew != "" {
				terr = models.CreateOneTimeToken(tx, user.ID, user.EmailChange, user.EmailChangeTokenNew, models.EmailChangeTokenNew)
				if terr != nil {
					terr = errors.Wrap(terr, "Database error creating email change token new in admin")
					return terr
				}
			}
		default:
			return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Invalid email action link type requested: %v", params.Type)
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
	var err error

	config := a.config
	maxFrequency := config.SMTP.MaxFrequency
	otpLength := config.Mailer.OtpLength

	if err = validateSentWithinFrequencyLimit(u.ConfirmationSentAt, maxFrequency); err != nil {
		return err
	}
	oldToken := u.ConfirmationToken
	otp := crypto.GenerateOtp(otpLength)

	token := crypto.GenerateTokenHash(u.GetEmail(), otp)
	u.ConfirmationToken = addFlowPrefixToToken(token, flowType)
	now := time.Now()
	if err = a.sendEmail(r, tx, u, mail.SignupVerification, otp, "", u.ConfirmationToken); err != nil {
		u.ConfirmationToken = oldToken
		if errors.Is(err, EmailRateLimitExceeded) {
			return apierrors.NewTooManyRequestsError(apierrors.ErrorCodeOverEmailSendRateLimit, EmailRateLimitExceeded.Error())
		} else if herr, ok := err.(*HTTPError); ok {
			return herr
		}
		return apierrors.NewInternalServerError("Error sending confirmation email").WithInternalError(err)
	}
	u.ConfirmationSentAt = &now
	if err := tx.UpdateOnly(u, "confirmation_token", "confirmation_sent_at"); err != nil {
		return apierrors.NewInternalServerError("Error sending confirmation email").WithInternalError(errors.Wrap(err, "Database error updating user for confirmation"))
	}

	if err := models.CreateOneTimeToken(tx, u.ID, u.GetEmail(), u.ConfirmationToken, models.ConfirmationToken); err != nil {
		return apierrors.NewInternalServerError("Error sending confirmation email").WithInternalError(errors.Wrap(err, "Database error creating confirmation token"))
	}

	return nil
}

func (a *API) sendInvite(r *http.Request, tx *storage.Connection, u *models.User) error {
	config := a.config
	otpLength := config.Mailer.OtpLength
	var err error
	oldToken := u.ConfirmationToken
	otp := crypto.GenerateOtp(otpLength)

	u.ConfirmationToken = crypto.GenerateTokenHash(u.GetEmail(), otp)
	now := time.Now()
	if err = a.sendEmail(r, tx, u, mail.InviteVerification, otp, "", u.ConfirmationToken); err != nil {
		u.ConfirmationToken = oldToken
		if errors.Is(err, EmailRateLimitExceeded) {
			return apierrors.NewTooManyRequestsError(apierrors.ErrorCodeOverEmailSendRateLimit, EmailRateLimitExceeded.Error())
		} else if herr, ok := err.(*HTTPError); ok {
			return herr
		}
		return apierrors.NewInternalServerError("Error sending invite email").WithInternalError(err)
	}
	u.InvitedAt = &now
	u.ConfirmationSentAt = &now
	err = tx.UpdateOnly(u, "confirmation_token", "confirmation_sent_at", "invited_at")
	if err != nil {
		return apierrors.NewInternalServerError("Error inviting user").WithInternalError(errors.Wrap(err, "Database error updating user for invite"))
	}

	err = models.CreateOneTimeToken(tx, u.ID, u.GetEmail(), u.ConfirmationToken, models.ConfirmationToken)
	if err != nil {
		return apierrors.NewInternalServerError("Error inviting user").WithInternalError(errors.Wrap(err, "Database error creating confirmation token for invite"))
	}

	return nil
}

func (a *API) sendPasswordRecovery(r *http.Request, tx *storage.Connection, u *models.User, flowType models.FlowType) error {
	config := a.config
	otpLength := config.Mailer.OtpLength

	if err := validateSentWithinFrequencyLimit(u.RecoverySentAt, config.SMTP.MaxFrequency); err != nil {
		return err
	}

	oldToken := u.RecoveryToken
	otp := crypto.GenerateOtp(otpLength)

	token := crypto.GenerateTokenHash(u.GetEmail(), otp)
	u.RecoveryToken = addFlowPrefixToToken(token, flowType)
	now := time.Now()
	if err := a.sendEmail(r, tx, u, mail.RecoveryVerification, otp, "", u.RecoveryToken); err != nil {
		u.RecoveryToken = oldToken
		if errors.Is(err, EmailRateLimitExceeded) {
			return apierrors.NewTooManyRequestsError(apierrors.ErrorCodeOverEmailSendRateLimit, EmailRateLimitExceeded.Error())
		} else if herr, ok := err.(*HTTPError); ok {
			return herr
		}
		return apierrors.NewInternalServerError("Error sending recovery email").WithInternalError(err)
	}
	u.RecoverySentAt = &now

	if err := tx.UpdateOnly(u, "recovery_token", "recovery_sent_at"); err != nil {
		return apierrors.NewInternalServerError("Error sending recovery email").WithInternalError(errors.Wrap(err, "Database error updating user for recovery"))
	}

	if err := models.CreateOneTimeToken(tx, u.ID, u.GetEmail(), u.RecoveryToken, models.RecoveryToken); err != nil {
		return apierrors.NewInternalServerError("Error sending recovery email").WithInternalError(errors.Wrap(err, "Database error creating recovery token"))
	}

	return nil
}

func (a *API) sendReauthenticationOtp(r *http.Request, tx *storage.Connection, u *models.User) error {
	config := a.config
	maxFrequency := config.SMTP.MaxFrequency
	otpLength := config.Mailer.OtpLength

	if err := validateSentWithinFrequencyLimit(u.ReauthenticationSentAt, maxFrequency); err != nil {
		return err
	}

	oldToken := u.ReauthenticationToken
	otp := crypto.GenerateOtp(otpLength)

	u.ReauthenticationToken = crypto.GenerateTokenHash(u.GetEmail(), otp)
	now := time.Now()

	if err := a.sendEmail(r, tx, u, mail.ReauthenticationVerification, otp, "", u.ReauthenticationToken); err != nil {
		u.ReauthenticationToken = oldToken
		if errors.Is(err, EmailRateLimitExceeded) {
			return apierrors.NewTooManyRequestsError(apierrors.ErrorCodeOverEmailSendRateLimit, EmailRateLimitExceeded.Error())
		} else if herr, ok := err.(*HTTPError); ok {
			return herr
		}
		return apierrors.NewInternalServerError("Error sending reauthentication email").WithInternalError(err)
	}
	u.ReauthenticationSentAt = &now
	if err := tx.UpdateOnly(u, "reauthentication_token", "reauthentication_sent_at"); err != nil {
		return apierrors.NewInternalServerError("Error sending reauthentication email").WithInternalError(errors.Wrap(err, "Database error updating user for reauthentication"))
	}

	if err := models.CreateOneTimeToken(tx, u.ID, u.GetEmail(), u.ReauthenticationToken, models.ReauthenticationToken); err != nil {
		return apierrors.NewInternalServerError("Error sending reauthentication email").WithInternalError(errors.Wrap(err, "Database error creating reauthentication token"))
	}

	return nil
}

func (a *API) sendMagicLink(r *http.Request, tx *storage.Connection, u *models.User, flowType models.FlowType) error {
	var err error
	config := a.config
	otpLength := config.Mailer.OtpLength

	// since Magic Link is just a recovery with a different template and behaviour
	// around new users we will reuse the recovery db timer to prevent potential abuse
	if err := validateSentWithinFrequencyLimit(u.RecoverySentAt, config.SMTP.MaxFrequency); err != nil {
		return err
	}

	oldToken := u.RecoveryToken
	otp := crypto.GenerateOtp(otpLength)

	token := crypto.GenerateTokenHash(u.GetEmail(), otp)
	u.RecoveryToken = addFlowPrefixToToken(token, flowType)

	now := time.Now()
	if err = a.sendEmail(r, tx, u, mail.MagicLinkVerification, otp, "", u.RecoveryToken); err != nil {
		u.RecoveryToken = oldToken
		if errors.Is(err, EmailRateLimitExceeded) {
			return apierrors.NewTooManyRequestsError(apierrors.ErrorCodeOverEmailSendRateLimit, EmailRateLimitExceeded.Error())
		} else if herr, ok := err.(*HTTPError); ok {
			return herr
		}
		return apierrors.NewInternalServerError("Error sending magic link email").WithInternalError(err)
	}
	u.RecoverySentAt = &now
	if err := tx.UpdateOnly(u, "recovery_token", "recovery_sent_at"); err != nil {
		return apierrors.NewInternalServerError("Error sending magic link email").WithInternalError(errors.Wrap(err, "Database error updating user for recovery"))
	}

	if err := models.CreateOneTimeToken(tx, u.ID, u.GetEmail(), u.RecoveryToken, models.RecoveryToken); err != nil {
		return apierrors.NewInternalServerError("Error sending magic link email").WithInternalError(errors.Wrap(err, "Database error creating recovery token"))
	}

	return nil
}

// sendEmailChange sends out an email change token to the new email.
func (a *API) sendEmailChange(r *http.Request, tx *storage.Connection, u *models.User, email string, flowType models.FlowType) error {
	config := a.config
	otpLength := config.Mailer.OtpLength

	if err := validateSentWithinFrequencyLimit(u.EmailChangeSentAt, config.SMTP.MaxFrequency); err != nil {
		return err
	}

	otpNew := crypto.GenerateOtp(otpLength)

	u.EmailChange = email
	token := crypto.GenerateTokenHash(u.EmailChange, otpNew)
	u.EmailChangeTokenNew = addFlowPrefixToToken(token, flowType)

	otpCurrent := ""
	if config.Mailer.SecureEmailChangeEnabled && u.GetEmail() != "" {
		otpCurrent = crypto.GenerateOtp(otpLength)

		currentToken := crypto.GenerateTokenHash(u.GetEmail(), otpCurrent)
		u.EmailChangeTokenCurrent = addFlowPrefixToToken(currentToken, flowType)
	}

	u.EmailChangeConfirmStatus = zeroConfirmation
	now := time.Now()

	if err := a.sendEmail(r, tx, u, mail.EmailChangeVerification, otpCurrent, otpNew, u.EmailChangeTokenNew); err != nil {
		if errors.Is(err, EmailRateLimitExceeded) {
			return apierrors.NewTooManyRequestsError(apierrors.ErrorCodeOverEmailSendRateLimit, EmailRateLimitExceeded.Error())
		} else if herr, ok := err.(*HTTPError); ok {
			return herr
		}
		return apierrors.NewInternalServerError("Error sending email change email").WithInternalError(err)
	}

	u.EmailChangeSentAt = &now
	if err := tx.UpdateOnly(
		u,
		"email_change_token_current",
		"email_change_token_new",
		"email_change",
		"email_change_sent_at",
		"email_change_confirm_status",
	); err != nil {
		return apierrors.NewInternalServerError("Error sending email change email").WithInternalError(errors.Wrap(err, "Database error updating user for email change"))
	}

	if u.EmailChangeTokenCurrent != "" {
		if err := models.CreateOneTimeToken(tx, u.ID, u.GetEmail(), u.EmailChangeTokenCurrent, models.EmailChangeTokenCurrent); err != nil {
			return apierrors.NewInternalServerError("Error sending email change email").WithInternalError(errors.Wrap(err, "Database error creating email change token current"))
		}
	}

	if u.EmailChangeTokenNew != "" {
		if err := models.CreateOneTimeToken(tx, u.ID, u.EmailChange, u.EmailChangeTokenNew, models.EmailChangeTokenNew); err != nil {
			return apierrors.NewInternalServerError("Error sending email change email").WithInternalError(errors.Wrap(err, "Database error creating email change token new"))
		}
	}

	return nil
}

func (a *API) validateEmail(email string) (string, error) {
	if email == "" {
		return "", apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "An email address is required")
	}
	if len(email) > 255 {
		return "", apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "An email address is too long")
	}
	if err := checkmail.ValidateFormat(email); err != nil {
		return "", apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Unable to validate email address: "+err.Error())
	}

	return strings.ToLower(email), nil
}

func validateSentWithinFrequencyLimit(sentAt *time.Time, frequency time.Duration) error {
	if sentAt != nil && sentAt.Add(frequency).After(time.Now()) {
		return apierrors.NewTooManyRequestsError(apierrors.ErrorCodeOverEmailSendRateLimit, generateFrequencyLimitErrorMessage(sentAt, frequency))
	}
	return nil
}

var emailLabelPattern = regexp.MustCompile("[+][^@]+@")

func (a *API) checkEmailAddressAuthorization(email string) bool {
	if len(a.config.External.Email.AuthorizedAddresses) > 0 {
		// allow labelled emails when authorization rules are in place
		normalized := emailLabelPattern.ReplaceAllString(email, "@")

		for _, authorizedAddress := range a.config.External.Email.AuthorizedAddresses {
			if strings.EqualFold(normalized, authorizedAddress) {
				return true
			}
		}

		return false
	}

	return true
}

func (a *API) sendEmail(r *http.Request, tx *storage.Connection, u *models.User, emailActionType, otp, otpNew, tokenHashWithPrefix string) error {
	ctx := r.Context()
	config := a.config
	referrerURL := utilities.GetReferrer(r, config)
	externalURL := getExternalHost(ctx)

	if emailActionType != mail.EmailChangeVerification {
		if u.GetEmail() != "" && !a.checkEmailAddressAuthorization(u.GetEmail()) {
			return apierrors.NewBadRequestError(apierrors.ErrorCodeEmailAddressNotAuthorized, "Email address %q cannot be used as it is not authorized", u.GetEmail())
		}
	} else {
		// first check that the user can update their address to the
		// new one in u.EmailChange
		if u.EmailChange != "" && !a.checkEmailAddressAuthorization(u.EmailChange) {
			return apierrors.NewBadRequestError(apierrors.ErrorCodeEmailAddressNotAuthorized, "Email address %q cannot be used as it is not authorized", u.EmailChange)
		}

		// if secure email change is enabled, check that the user
		// account (which could have been created before the authorized
		// address authorization restriction was enabled) can even
		// receive the confirmation message to the existing address
		if config.Mailer.SecureEmailChangeEnabled && u.GetEmail() != "" && !a.checkEmailAddressAuthorization(u.GetEmail()) {
			return apierrors.NewBadRequestError(apierrors.ErrorCodeEmailAddressNotAuthorized, "Email address %q cannot be used as it is not authorized", u.GetEmail())
		}
	}

	// if the number of events is set to zero, we immediately apply rate limits.
	if config.RateLimitEmailSent.Events == 0 {
		emailRateLimitCounter.Add(
			ctx,
			1,
			metric.WithAttributeSet(attribute.NewSet(attribute.String("path", r.URL.Path))),
		)
		return EmailRateLimitExceeded
	}

	// TODO(km): Deprecate this behaviour - rate limits should still be applied to autoconfirm
	if !config.Mailer.Autoconfirm {
		// apply rate limiting before the email is sent out
		if ok := a.limiterOpts.Email.Allow(); !ok {
			emailRateLimitCounter.Add(
				ctx,
				1,
				metric.WithAttributeSet(attribute.NewSet(attribute.String("path", r.URL.Path))),
			)
			return EmailRateLimitExceeded
		}
	}

	if config.Hook.SendEmail.Enabled {
		// When secure email change is disabled, we place the token for the new email on emailData.Token
		if emailActionType == mail.EmailChangeVerification && !config.Mailer.SecureEmailChangeEnabled && u.GetEmail() != "" {
			otp = otpNew
		}

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
		input := v0hooks.SendEmailInput{
			User:      u,
			EmailData: emailData,
		}
		output := v0hooks.SendEmailOutput{}
		return a.hooksMgr.InvokeHook(tx, r, &input, &output)
	}

	mr := a.Mailer()
	var err error
	switch emailActionType {
	case mail.SignupVerification:
		err = mr.ConfirmationMail(r, u, otp, referrerURL, externalURL)
	case mail.MagicLinkVerification:
		err = mr.MagicLinkMail(r, u, otp, referrerURL, externalURL)
	case mail.ReauthenticationVerification:
		err = mr.ReauthenticateMail(r, u, otp)
	case mail.RecoveryVerification:
		err = mr.RecoveryMail(r, u, otp, referrerURL, externalURL)
	case mail.InviteVerification:
		err = mr.InviteMail(r, u, otp, referrerURL, externalURL)
	case mail.EmailChangeVerification:
		err = mr.EmailChangeMail(r, u, otpNew, otp, referrerURL, externalURL)
	default:
		err = errors.New("invalid email action type")
	}

	switch {
	case errors.Is(err, mail.ErrInvalidEmailAddress),
		errors.Is(err, mail.ErrInvalidEmailFormat),
		errors.Is(err, mail.ErrInvalidEmailDNS):
		return apierrors.NewBadRequestError(
			apierrors.ErrorCodeEmailAddressInvalid,
			"Email address %q is invalid",
			u.GetEmail())
	default:
		return err
	}
}
