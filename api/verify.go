package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
	"github.com/sethvargo/go-password/password"
)

var (
	// indicates that a user should be redirected due to an error
	redirectWithQueryError = errors.New("redirect user")
)

const (
	signupVerification      = "signup"
	recoveryVerification    = "recovery"
	inviteVerification      = "invite"
	magicLinkVerification   = "magiclink"
	emailChangeVerification = "email_change"
	smsVerification         = "sms"
	phoneChangeVerification = "phone_change"
)

const (
	zeroConfirmation int = iota
	singleConfirmation
)

// VerifyParams are the parameters the Verify endpoint accepts
type VerifyParams struct {
	Type       string `json:"type"`
	Token      string `json:"token"`
	Password   string `json:"password"`
	Email      string `json:"email"`
	Phone      string `json:"phone"`
	RedirectTo string `json:"redirect_to"`
}

// Verify exchanges a confirmation or recovery token to a refresh token
func (a *API) Verify(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	config := a.getConfig(ctx)

	params := &VerifyParams{}

	switch r.Method {
	// GET only supports signup type
	case "GET":
		params.Token = r.FormValue("token")
		params.Password = ""
		params.Type = r.FormValue("type")
		params.RedirectTo = a.getRedirectURLOrReferrer(r, r.FormValue("redirect_to"))
	case "POST":
		jsonDecoder := json.NewDecoder(r.Body)
		if err := jsonDecoder.Decode(params); err != nil {
			return badRequestError("Could not read verification params: %v", err)
		}
		params.RedirectTo = a.getRedirectURLOrReferrer(r, params.RedirectTo)
	default:
		unprocessableEntityError("Only GET and POST methods are supported.")
	}

	if params.Token == "" {
		return unprocessableEntityError("Verify requires a token")
	}

	var (
		user  *models.User
		err   error
		token *AccessTokenResponse
	)

	err = a.db.Transaction(func(tx *storage.Connection) error {
		var terr error
		aud := a.requestAud(ctx, r)
		user, terr = a.verifyUserAndToken(ctx, tx, params, aud)
		if terr != nil {
			return terr
		}

		switch params.Type {
		case signupVerification, inviteVerification:
			user, terr = a.signupVerify(ctx, tx, user)
		case recoveryVerification, magicLinkVerification:
			user, terr = a.recoverVerify(ctx, tx, user)
		case emailChangeVerification:
			user, terr = a.emailChangeVerify(ctx, tx, params, user)
			if user == nil && terr == nil {
				// when double confirmation is required
				rurl := a.prepRedirectURL("Confirmation link accepted. Please proceed to confirm link sent to the other email", params.RedirectTo)
				http.Redirect(w, r, rurl, http.StatusSeeOther)
				return nil
			}
		case smsVerification, phoneChangeVerification:
			user, terr = a.smsVerify(ctx, tx, user, params.Type)
		default:
			return unprocessableEntityError("Verify requires a verification type")
		}

		if terr != nil {
			return terr
		}

		token, terr = a.issueRefreshToken(ctx, tx, user)
		if terr != nil {
			return terr
		}

		if terr = a.setCookieTokens(config, token, false, w); terr != nil {
			return internalServerError("Failed to set JWT cookie. %s", terr)
		}
		return nil
	})

	if err != nil {
		if r.Method == http.MethodPost {
			// do not redirect POST requests
			return err
		}
		var herr *HTTPError
		if errors.As(err, &herr) {
			if errors.Is(herr.InternalError, redirectWithQueryError) {
				rurl := a.prepErrorRedirectURL(herr, r, params.RedirectTo)
				http.Redirect(w, r, rurl, http.StatusSeeOther)
				return nil
			}
		}
	}

	// GET requests should return to the app site after confirmation
	switch r.Method {
	case "GET":
		rurl := params.RedirectTo
		if token != nil {
			q := url.Values{}
			q.Set("access_token", token.Token)
			q.Set("token_type", token.TokenType)
			q.Set("expires_in", strconv.Itoa(token.ExpiresIn))
			q.Set("refresh_token", token.RefreshToken)
			q.Set("type", params.Type)
			rurl += "#" + q.Encode()
		}
		http.Redirect(w, r, rurl, http.StatusSeeOther)
	case "POST":
		return sendJSON(w, http.StatusOK, token)
	}

	return nil
}

func (a *API) signupVerify(ctx context.Context, conn *storage.Connection, user *models.User) (*models.User, error) {
	instanceID := getInstanceID(ctx)
	config := a.getConfig(ctx)

	err := conn.Transaction(func(tx *storage.Connection) error {
		var terr error
		if user.EncryptedPassword == "" {
			if user.InvitedAt != nil {
				// sign them up with temporary password, and require application
				// to present the user with a password set form
				password, err := password.Generate(64, 10, 0, false, true)
				if err != nil {
					internalServerError("error creating user").WithInternalError(err)
				}
				if terr = user.UpdatePassword(tx, password); terr != nil {
					return internalServerError("Error storing password").WithInternalError(terr)
				}
			}
		}

		if terr = models.NewAuditLogEntry(tx, instanceID, user, models.UserSignedUpAction, nil); terr != nil {
			return terr
		}

		if terr = triggerEventHooks(ctx, tx, SignupEvent, user, instanceID, config); terr != nil {
			return terr
		}

		if terr = user.Confirm(tx); terr != nil {
			return internalServerError("Error confirming user").WithInternalError(terr)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (a *API) recoverVerify(ctx context.Context, conn *storage.Connection, user *models.User) (*models.User, error) {
	instanceID := getInstanceID(ctx)
	config := a.getConfig(ctx)

	err := conn.Transaction(func(tx *storage.Connection) error {
		var terr error
		if terr = user.Recover(tx); terr != nil {
			return terr
		}
		if !user.IsConfirmed() {
			if terr = models.NewAuditLogEntry(tx, instanceID, user, models.UserSignedUpAction, nil); terr != nil {
				return terr
			}

			if terr = triggerEventHooks(ctx, tx, SignupEvent, user, instanceID, config); terr != nil {
				return terr
			}
			if terr = user.Confirm(tx); terr != nil {
				return terr
			}
		} else {
			if terr = models.NewAuditLogEntry(tx, instanceID, user, models.LoginAction, nil); terr != nil {
				return terr
			}
			if terr = triggerEventHooks(ctx, tx, LoginEvent, user, instanceID, config); terr != nil {
				return terr
			}
		}
		return nil
	})

	if err != nil {
		return nil, internalServerError("Database error updating user").WithInternalError(err)
	}
	return user, nil
}

func (a *API) smsVerify(ctx context.Context, conn *storage.Connection, user *models.User, otpType string) (*models.User, error) {
	instanceID := getInstanceID(ctx)
	config := a.getConfig(ctx)

	err := conn.Transaction(func(tx *storage.Connection) error {
		var terr error
		if terr = models.NewAuditLogEntry(tx, instanceID, user, models.UserSignedUpAction, nil); terr != nil {
			return terr
		}

		if terr = triggerEventHooks(ctx, tx, SignupEvent, user, instanceID, config); terr != nil {
			return terr
		}

		if otpType == smsVerification {
			if terr = user.ConfirmPhone(tx); terr != nil {
				return internalServerError("Error confirming user").WithInternalError(terr)
			}
		} else if otpType == phoneChangeVerification {
			if terr = user.ConfirmPhoneChange(tx); terr != nil {
				return internalServerError("Error confirming user").WithInternalError(terr)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (a *API) prepErrorRedirectURL(err *HTTPError, r *http.Request, rurl string) string {
	q := url.Values{}

	log := getLogEntry(r)
	log.Error(err.Message)

	if str, ok := oauthErrorMap[err.Code]; ok {
		q.Set("error", str)
	}
	q.Set("error_code", strconv.Itoa(err.Code))
	q.Set("error_description", err.Message)
	return rurl + "#" + q.Encode()
}

func (a *API) prepRedirectURL(message string, rurl string) string {
	q := url.Values{}
	q.Set("message", message)
	return rurl + "#" + q.Encode()
}

func (a *API) emailChangeVerify(ctx context.Context, conn *storage.Connection, params *VerifyParams, user *models.User) (*models.User, error) {
	instanceID := getInstanceID(ctx)
	config := a.getConfig(ctx)

	if config.Mailer.SecureEmailChangeEnabled && user.EmailChangeConfirmStatus == zeroConfirmation && user.GetEmail() != "" {
		err := conn.Transaction(func(tx *storage.Connection) error {
			user.EmailChangeConfirmStatus = singleConfirmation
			if params.Token == user.EmailChangeTokenCurrent {
				user.EmailChangeTokenCurrent = ""
			} else if params.Token == user.EmailChangeTokenNew {
				user.EmailChangeTokenNew = ""
			}
			if terr := tx.UpdateOnly(user, "email_change_confirm_status", "email_change_token_current", "email_change_token_new"); terr != nil {
				return terr
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		return nil, nil
	}

	// one email is confirmed at this point
	err := conn.Transaction(func(tx *storage.Connection) error {
		var terr error

		if terr = models.NewAuditLogEntry(tx, instanceID, user, models.UserModifiedAction, nil); terr != nil {
			return terr
		}

		if terr = triggerEventHooks(ctx, tx, EmailChangeEvent, user, instanceID, config); terr != nil {
			return terr
		}

		if terr = user.ConfirmEmailChange(tx, zeroConfirmation); terr != nil {
			return internalServerError("Error confirm email").WithInternalError(terr)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return user, nil
}

// verifyUserAndToken verifies the token associated to the user based on the verify type
func (a *API) verifyUserAndToken(ctx context.Context, conn *storage.Connection, params *VerifyParams, aud string) (*models.User, error) {
	instanceID := getInstanceID(ctx)
	config := getConfig(ctx)

	var user *models.User
	var err error
	if isUrlVerification(params) {
		switch params.Type {
		case signupVerification, inviteVerification:
			user, err = models.FindUserByConfirmationToken(conn, params.Token)
		case recoveryVerification, magicLinkVerification:
			user, err = models.FindUserByRecoveryToken(conn, params.Token)
		case emailChangeVerification:
			user, err = models.FindUserByEmailChangeToken(conn, params.Token)
		}
	} else if params.Type == smsVerification || params.Type == phoneChangeVerification {
		if params.Phone == "" {
			return nil, unprocessableEntityError("Sms Verification requires a phone number")
		}
		params.Phone, err = a.validatePhone(params.Phone)
		if err != nil {
			return nil, err
		}
		user, err = models.FindUserByPhoneAndAudience(conn, instanceID, params.Phone, aud)
	} else if params.Email != "" {
		if err := a.validateEmail(ctx, params.Email); err != nil {
			return nil, unprocessableEntityError("Invalid email format").WithInternalError(err)
		}
		user, err = models.FindUserByEmailAndAudience(conn, instanceID, params.Email, aud)
	}

	if err != nil {
		if models.IsNotFoundError(err) {
			return nil, notFoundError(err.Error()).WithInternalError(redirectWithQueryError)
		}
		return nil, internalServerError("Database error finding user").WithInternalError(err)
	}

	if user.IsBanned() {
		return nil, unauthorizedError("Error confirming user").WithInternalError(redirectWithQueryError)
	}

	var isValid bool
	mailerOtpExpiresAt := time.Second * time.Duration(config.Mailer.OtpExp)
	smsOtpExpiresAt := time.Second * time.Duration(config.Sms.OtpExp)
	switch params.Type {
	case signupVerification, inviteVerification:
		isValid = isOtpValid(params.Token, user.ConfirmationToken, user.ConfirmationSentAt.Add(mailerOtpExpiresAt))
	case recoveryVerification, magicLinkVerification:
		isValid = isOtpValid(params.Token, user.RecoveryToken, user.RecoverySentAt.Add(mailerOtpExpiresAt))
	case emailChangeVerification:
		expiresAt := user.EmailChangeSentAt.Add(mailerOtpExpiresAt)
		isValid = isOtpValid(params.Token, user.EmailChangeTokenCurrent, expiresAt) || isOtpValid(params.Token, user.EmailChangeTokenNew, expiresAt)
		if !isValid {
			// reset email confirmation status
			user.EmailChangeConfirmStatus = zeroConfirmation
			err = conn.UpdateOnly(user, "email_change_confirm_status")
		}
	case phoneChangeVerification:
		isValid = isOtpValid(params.Token, user.PhoneChangeToken, user.PhoneChangeSentAt.Add(smsOtpExpiresAt))
	case smsVerification:
		isValid = isOtpValid(params.Token, user.ConfirmationToken, user.ConfirmationSentAt.Add(smsOtpExpiresAt))
	}

	if !isValid || err != nil {
		return nil, expiredTokenError("Token has expired or is invalid").WithInternalError(redirectWithQueryError)
	}
	return user, nil
}

// isOtpValid checks the actual otp sent against the expected otp and ensures that it's within the valid window
func isOtpValid(actual, expected string, expiresAt time.Time) bool {
	return time.Now().Before(expiresAt) && (actual == expected)
}

func isUrlVerification(params *VerifyParams) bool {
	isPhoneVerification := params.Type == smsVerification || params.Type == phoneChangeVerification
	return !isPhoneVerification && params.Email == ""
}
