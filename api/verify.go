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
		unprocessableEntityError("Sorry, only GET and POST methods are supported.")
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
		switch params.Type {
		case signupVerification, inviteVerification:
			user, terr = a.signupVerify(ctx, tx, params)
		case recoveryVerification, magicLinkVerification:
			user, terr = a.recoverVerify(ctx, tx, params)
		case emailChangeVerification:
			user, terr = a.emailChangeVerify(ctx, tx, params)
			if user == nil && terr == nil {
				// when double confirmation is required
				rurl := a.prepRedirectURL("Confirmation link accepted. Please proceed to confirm link sent to the other email", params.RedirectTo)
				http.Redirect(w, r, rurl, http.StatusSeeOther)
				return nil
			}
		case smsVerification:
			if params.Phone == "" {
				return unprocessableEntityError("Sms Verification requires a phone number")
			}
			params.Phone = a.formatPhoneNumber(params.Phone)
			if isValid := a.validateE164Format(params.Phone); !isValid {
				return unprocessableEntityError("Invalid phone number format")
			}
			aud := a.requestAud(ctx, r)
			user, terr = a.smsVerify(ctx, tx, params, aud)
		default:
			return unprocessableEntityError("Verify requires a verification type")
		}

		if terr != nil {
			var e *HTTPError
			if errors.As(terr, &e) {
				if errors.Is(e.InternalError, redirectWithQueryError) {
					rurl := a.prepErrorRedirectURL(e, r, params.RedirectTo)
					http.Redirect(w, r, rurl, http.StatusSeeOther)
					return nil
				}
			}
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
		return err
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

func (a *API) signupVerify(ctx context.Context, conn *storage.Connection, params *VerifyParams) (*models.User, error) {
	instanceID := getInstanceID(ctx)
	config := a.getConfig(ctx)

	user, err := models.FindUserByConfirmationToken(conn, params.Token)
	if err != nil {
		if models.IsNotFoundError(err) {
			return nil, notFoundError(err.Error()).WithInternalError(redirectWithQueryError)
		}
		return nil, internalServerError("Database error finding user").WithInternalError(err)
	}

	if user.IsBanned() {
		return nil, unauthorizedError("Error confirming user").WithInternalError(redirectWithQueryError)
	}

	nextDay := user.ConfirmationSentAt.Add(24 * time.Hour)
	if user.ConfirmationSentAt != nil && time.Now().After(nextDay) {
		return nil, expiredTokenError("Confirmation token expired").WithInternalError(redirectWithQueryError)
	}

	err = conn.Transaction(func(tx *storage.Connection) error {
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

func (a *API) recoverVerify(ctx context.Context, conn *storage.Connection, params *VerifyParams) (*models.User, error) {
	instanceID := getInstanceID(ctx)
	config := a.getConfig(ctx)
	user, err := models.FindUserByRecoveryToken(conn, params.Token)
	if err != nil {
		if models.IsNotFoundError(err) {
			return nil, notFoundError(err.Error()).WithInternalError(redirectWithQueryError)
		}
		return nil, internalServerError("Database error finding user").WithInternalError(err)
	}

	if user.IsBanned() {
		return nil, unauthorizedError("Error confirming user").WithInternalError(redirectWithQueryError)
	}

	nextDay := user.RecoverySentAt.Add(24 * time.Hour)
	if user.RecoverySentAt != nil && time.Now().After(nextDay) {
		return nil, expiredTokenError("Recovery token expired").WithInternalError(redirectWithQueryError)
	}

	err = conn.Transaction(func(tx *storage.Connection) error {
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
		}
		return nil
	})

	if err != nil {
		return nil, internalServerError("Database error updating user").WithInternalError(err)
	}
	return user, nil
}

func (a *API) smsVerify(ctx context.Context, conn *storage.Connection, params *VerifyParams, aud string) (*models.User, error) {
	instanceID := getInstanceID(ctx)
	config := a.getConfig(ctx)
	user, err := models.FindUserByPhoneAndAudience(conn, instanceID, params.Phone, aud)
	if err != nil {
		if models.IsNotFoundError(err) {
			return nil, notFoundError(err.Error()).WithInternalError(redirectWithQueryError)
		}
		return nil, internalServerError("Database error finding user").WithInternalError(err)
	}

	if user.IsBanned() {
		return nil, unauthorizedError("Error confirming user").WithInternalError(redirectWithQueryError)
	}

	now := time.Now()
	expiresAt := user.ConfirmationSentAt.Add(time.Second * time.Duration(config.Sms.OtpExp))

	// check if token has expired or is invalid
	if isOtpValid := now.Before(expiresAt) && params.Token == user.ConfirmationToken; !isOtpValid {
		return nil, expiredTokenError("Otp has expired or is invalid").WithInternalError(redirectWithQueryError)
	}

	err = conn.Transaction(func(tx *storage.Connection) error {
		var terr error
		if terr = models.NewAuditLogEntry(tx, instanceID, user, models.UserSignedUpAction, nil); terr != nil {
			return terr
		}

		if terr = triggerEventHooks(ctx, tx, SignupEvent, user, instanceID, config); terr != nil {
			return terr
		}

		if terr = user.ConfirmPhone(tx); terr != nil {
			return internalServerError("Error confirming user").WithInternalError(terr)
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

func (a *API) emailChangeVerify(ctx context.Context, conn *storage.Connection, params *VerifyParams) (*models.User, error) {
	instanceID := getInstanceID(ctx)
	config := a.getConfig(ctx)
	user, err := models.FindUserByEmailChangeToken(conn, params.Token)
	if err != nil {
		if models.IsNotFoundError(err) {
			return nil, notFoundError(err.Error()).WithInternalError(redirectWithQueryError)
		}
		return nil, internalServerError("Database error finding user").WithInternalError(err)
	}

	if user.IsBanned() {
		return nil, unauthorizedError("Error confirming user").WithInternalError(redirectWithQueryError)
	}

	nextDay := user.EmailChangeSentAt.Add(24 * time.Hour)
	if user.EmailChangeSentAt != nil && time.Now().After(nextDay) {
		err = a.db.Transaction(func(tx *storage.Connection) error {
			user.EmailChangeConfirmStatus = zeroConfirmation
			return tx.UpdateOnly(user, "email_change_confirm_status")
		})
		if err != nil {
			return nil, err
		}
		return nil, expiredTokenError("Email change token expired").WithInternalError(redirectWithQueryError)
	}

	if config.Mailer.SecureEmailChangeEnabled {
		if user.EmailChangeConfirmStatus == zeroConfirmation {
			err = a.db.Transaction(func(tx *storage.Connection) error {
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
	}

	// one email is confirmed at this point
	err = a.db.Transaction(func(tx *storage.Connection) error {
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
