package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/netlify/gotrue/conf"
	"github.com/netlify/gotrue/crypto"
	"github.com/netlify/gotrue/mailer"
	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
	"github.com/pkg/errors"
	"github.com/sethvargo/go-password/password"
)

var (
	MaxFrequencyLimitError error = errors.New("Frequency limit reached")
	configFile                   = ""
)

type GenerateLinkParams struct {
	Type       string                 `json:"type"`
	Email      string                 `json:"email"`
	Password   string                 `json:"password"`
	Data       map[string]interface{} `json:"data"`
	RedirectTo string                 `json:"redirect_to"`
}

func (a *API) GenerateLink(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	config := a.getConfig(ctx)
	mailer := a.Mailer(ctx)
	instanceID := getInstanceID(ctx)
	adminUser := getAdminUser(ctx)

	params := &GenerateLinkParams{}
	jsonDecoder := json.NewDecoder(r.Body)

	if err := jsonDecoder.Decode(params); err != nil {
		return badRequestError("Could not read body: %v", err)
	}

	if err := a.validateEmail(ctx, params.Email); err != nil {
		return err
	}

	aud := a.requestAud(ctx, r)
	user, err := models.FindUserByEmailAndAudience(a.db, instanceID, params.Email, aud)
	if err != nil {
		if models.IsNotFoundError(err) {
			if params.Type == "magiclink" {
				params.Type = "signup"
				params.Password, err = password.Generate(64, 10, 0, false, true)
				if err != nil {
					return internalServerError("error creating user").WithInternalError(err)
				}
			} else if params.Type == "recovery" {
				return notFoundError(err.Error())
			}
		} else {
			return internalServerError("Database error finding user").WithInternalError(err)
		}
	}

	var url string
	referrer := a.getRedirectURLOrReferrer(r, params.RedirectTo)
	now := time.Now()
	otp, err := crypto.GenerateOtp(config.Mailer.OtpLength)
	if err != nil {
		return err
	}
	err = a.db.Transaction(func(tx *storage.Connection) error {
		var terr error
		switch params.Type {
		case "magiclink", "recovery":
			if terr = models.NewAuditLogEntry(tx, instanceID, user, models.UserRecoveryRequestedAction, "", nil); terr != nil {
				return terr
			}
			user.RecoveryToken = fmt.Sprintf("%x", sha256.Sum224([]byte(user.GetEmail()+otp)))
			user.RecoverySentAt = &now
			terr = errors.Wrap(tx.UpdateOnly(user, "recovery_token", "recovery_sent_at"), "Database error updating user for recovery")
		case "invite":
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
				user, terr = a.signupNewUser(ctx, tx, signupParams)
				if terr != nil {
					return terr
				}
			}
			if terr = models.NewAuditLogEntry(tx, instanceID, adminUser, models.UserInvitedAction, "", map[string]interface{}{
				"user_id":    user.ID,
				"user_email": user.Email,
			}); terr != nil {
				return terr
			}
			user.ConfirmationToken = fmt.Sprintf("%x", sha256.Sum224([]byte(user.GetEmail()+otp)))
			user.ConfirmationSentAt = &now
			user.InvitedAt = &now
			terr = errors.Wrap(tx.UpdateOnly(user, "confirmation_token", "confirmation_sent_at", "invited_at"), "Database error updating user for invite")
		case "signup":
			if user != nil {
				if user.IsConfirmed() {
					return unprocessableEntityError(DuplicateEmailMsg)
				}
				if err := user.UpdateUserMetaData(tx, params.Data); err != nil {
					return internalServerError("Database error updating user").WithInternalError(err)
				}
			} else {
				if params.Password == "" {
					return unprocessableEntityError("Signup requires a valid password")
				}
				if len(params.Password) < config.PasswordMinLength {
					return unprocessableEntityError(fmt.Sprintf("Password should be at least %d characters", config.PasswordMinLength))
				}
				signupParams := &SignupParams{
					Email:    params.Email,
					Password: params.Password,
					Data:     params.Data,
					Provider: "email",
					Aud:      aud,
				}
				user, terr = a.signupNewUser(ctx, tx, signupParams)
				if terr != nil {
					return terr
				}
			}
			user.ConfirmationToken = fmt.Sprintf("%x", sha256.Sum224([]byte(user.GetEmail()+otp)))
			user.ConfirmationSentAt = &now
			terr = errors.Wrap(tx.UpdateOnly(user, "confirmation_token", "confirmation_sent_at"), "Database error updating user for confirmation")
		default:
			return badRequestError("Invalid email action link type requested: %v", params.Type)
		}

		if terr != nil {
			return terr
		}

		url, terr = mailer.GetEmailActionLink(user, params.Type, referrer)
		if terr != nil {
			return terr
		}
		return nil
	})

	if err != nil {
		return err
	}

	resp := make(map[string]interface{})
	u, err := json.Marshal(user)
	if err != nil {
		return internalServerError("User serialization error").WithInternalError(err)
	}
	if err = json.Unmarshal(u, &resp); err != nil {
		return internalServerError("User serialization error").WithInternalError(err)
	}
	resp["action_link"] = url

	return sendJSON(w, http.StatusOK, resp)
}

func sendConfirmation(tx *storage.Connection, u *models.User, mailer mailer.Mailer, maxFrequency time.Duration, referrerURL string, otpLength int) error {
	var err error
	if u.ConfirmationSentAt != nil && !u.ConfirmationSentAt.Add(maxFrequency).Before(time.Now()) {
		return MaxFrequencyLimitError
	}
	oldToken := u.ConfirmationToken
	otp, err := crypto.GenerateOtp(otpLength)
	if err != nil {
		return err
	}
	u.ConfirmationToken = fmt.Sprintf("%x", sha256.Sum224([]byte(u.GetEmail()+otp)))
	now := time.Now()
	if err := mailer.ConfirmationMail(u, otp, referrerURL); err != nil {
		u.ConfirmationToken = oldToken
		return errors.Wrap(err, "Error sending confirmation email")
	}
	u.ConfirmationSentAt = &now
	return errors.Wrap(tx.UpdateOnly(u, "confirmation_token", "confirmation_sent_at"), "Database error updating user for confirmation")
}

func sendInvite(tx *storage.Connection, u *models.User, mailer mailer.Mailer, referrerURL string, otpLength int) error {
	var err error
	oldToken := u.ConfirmationToken
	otp, err := crypto.GenerateOtp(otpLength)
	if err != nil {
		return err
	}
	u.ConfirmationToken = fmt.Sprintf("%x", sha256.Sum224([]byte(u.GetEmail()+otp)))
	now := time.Now()
	if err := mailer.InviteMail(u, otp, referrerURL); err != nil {
		u.ConfirmationToken = oldToken
		return errors.Wrap(err, "Error sending invite email")
	}
	u.InvitedAt = &now
	u.ConfirmationSentAt = &now
	return errors.Wrap(tx.UpdateOnly(u, "confirmation_token", "confirmation_sent_at", "invited_at"), "Database error updating user for invite")
}

func (a *API) sendPasswordRecovery(tx *storage.Connection, u *models.User, mailer mailer.Mailer, maxFrequency time.Duration, referrerURL string, otpLength int) error {
	var err error
	if u.RecoverySentAt != nil && !u.RecoverySentAt.Add(maxFrequency).Before(time.Now()) {
		return MaxFrequencyLimitError
	}

	oldToken := u.RecoveryToken
	otp, err := crypto.GenerateOtp(otpLength)
	if err != nil {
		return err
	}
	u.RecoveryToken = fmt.Sprintf("%x", sha256.Sum224([]byte(u.GetEmail()+otp)))
	now := time.Now()
	if err := mailer.RecoveryMail(u, otp, referrerURL); err != nil {
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
	u.ReauthenticationToken = fmt.Sprintf("%x", sha256.Sum224([]byte(u.GetEmail()+otp)))
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

func (a *API) sendMagicLink(tx *storage.Connection, u *models.User, mailer mailer.Mailer, maxFrequency time.Duration, referrerURL string, otpLength int) error {
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
	u.RecoveryToken = fmt.Sprintf("%x", sha256.Sum224([]byte(u.GetEmail()+otp)))
	now := time.Now()
	if err := mailer.MagicLinkMail(u, otp, referrerURL); err != nil {
		u.RecoveryToken = oldToken
		return errors.Wrap(err, "Error sending magic link email")
	}
	u.RecoverySentAt = &now
	return errors.Wrap(tx.UpdateOnly(u, "recovery_token", "recovery_sent_at"), "Database error updating user for recovery")
}

// sendEmailChange sends out an email change token to the new email.
func (a *API) sendEmailChange(tx *storage.Connection, config *conf.Configuration, u *models.User, mailer mailer.Mailer, email string, referrerURL string, otpLength int) error {
	var err error
	otpNew, err := crypto.GenerateOtp(otpLength)
	if err != nil {
		return err
	}
	u.EmailChangeTokenNew = fmt.Sprintf("%x", sha256.Sum224([]byte(u.EmailChange+otpNew)))

	otpCurrent := ""
	if config.Mailer.SecureEmailChangeEnabled && u.GetEmail() != "" {
		otpCurrent, err = crypto.GenerateOtp(otpLength)
		if err != nil {
			return err
		}
		u.EmailChangeTokenCurrent = fmt.Sprintf("%x", sha256.Sum224([]byte(u.GetEmail()+otpCurrent)))
		if err != nil {
			return err
		}
	}
	u.EmailChange = email
	u.EmailChangeConfirmStatus = zeroConfirmation
	now := time.Now()
	if err := mailer.EmailChangeMail(u, otpNew, otpCurrent, referrerURL); err != nil {
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

func (a *API) validateEmail(ctx context.Context, email string) error {
	if email == "" {
		return unprocessableEntityError("An email address is required")
	}
	mailer := a.Mailer(ctx)
	if err := mailer.ValidateEmail(email); err != nil {
		return unprocessableEntityError("Unable to validate email address: " + err.Error())
	}
	return nil
}
