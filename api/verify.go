package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
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

const (
	// v1 uses crypto.SecureToken()
	v1OtpLength      = 22
	sum224HashLength = 28
)

// Only applicable when SECURE_EMAIL_CHANGE_ENABLED
const singleConfirmationAccepted = "Confirmation link accepted. Please proceed to confirm link sent to the other email"

// VerifyParams are the parameters the Verify endpoint accepts
type VerifyParams struct {
	Type       string `json:"type"`
	Token      string `json:"token"`
	Email      string `json:"email"`
	Phone      string `json:"phone"`
	RedirectTo string `json:"redirect_to"`
}

// Verify exchanges a confirmation or recovery token to a refresh token
func (a *API) Verify(w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case http.MethodGet:
		return a.verifyGet(w, r)
	case http.MethodPost:
		return a.verifyPost(w, r)
	default:
		return unprocessableEntityError("Only GET and POST methods are supported.")
	}
}

func (a *API) verifyGet(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	config := a.getConfig(ctx)
	params := &VerifyParams{}
	params.Token = r.FormValue("token")
	params.Type = r.FormValue("type")
	params.RedirectTo = a.getRedirectURLOrReferrer(r, r.FormValue("redirect_to"))

	var (
		user  *models.User
		err   error
		token *AccessTokenResponse
	)

	err = a.db.Transaction(func(tx *storage.Connection) error {
		var terr error
		if params.Token == "" {
			return badRequestError("Verify requires a token")
		}
		if len(params.Token) > v1OtpLength {
			// token follows the v2 format and includes "-"
			params.Token = strings.ReplaceAll(params.Token, "-", "")
		}
		if params.Type == "" {
			return badRequestError("Verify requires a verification type")
		}
		aud := a.requestAud(ctx, r)
		user, terr = a.verifyEmailLink(ctx, tx, params, aud)
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
				rurl := a.prepRedirectURL(singleConfirmationAccepted, params.RedirectTo)
				http.Redirect(w, r, rurl, http.StatusSeeOther)
				return nil
			}
		default:
			return unprocessableEntityError("Unsupported verification type")
		}

		if terr != nil {
			return terr
		}

		token, terr = a.issueRefreshToken(ctx, tx, user, nil)
		if terr != nil {
			return terr
		}

		if terr = a.setCookieTokens(config, token, false, w); terr != nil {
			return internalServerError("Failed to set JWT cookie. %s", terr)
		}
		return nil
	})

	if err != nil {
		var herr *HTTPError
		if errors.As(err, &herr) {
			rurl := a.prepErrorRedirectURL(herr, r, params.RedirectTo)
			http.Redirect(w, r, rurl, http.StatusSeeOther)
			return nil
		}
	}

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
	return nil
}

func (a *API) verifyPost(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	config := a.getConfig(ctx)
	params := &VerifyParams{}
	jsonDecoder := json.NewDecoder(r.Body)
	if err := jsonDecoder.Decode(params); err != nil {
		return badRequestError("Could not read verification params: %v", err)
	}

	if params.Token == "" {
		return badRequestError("Verify requires a token")
	}
	if len(params.Token) > v1OtpLength {
		// token follows the v2 format and includes "-"
		params.Token = strings.ReplaceAll(params.Token, "-", "")
	}

	if params.Type == "" {
		return badRequestError("Verify requires a verification type")
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
				return sendJSON(w, http.StatusOK, map[string]string{
					"msg":  singleConfirmationAccepted,
					"code": strconv.Itoa(http.StatusOK),
				})
			}
		case smsVerification, phoneChangeVerification:
			user, terr = a.smsVerify(ctx, tx, user, params.Type)
		default:
			return unprocessableEntityError("Unsupported verification type")
		}

		if terr != nil {
			return terr
		}

		token, terr = a.issueRefreshToken(ctx, tx, user, nil)
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
	return sendJSON(w, http.StatusOK, token)
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

		if terr = models.NewAuditLogEntry(tx, instanceID, user, models.UserSignedUpAction, "", nil); terr != nil {
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
			if terr = models.NewAuditLogEntry(tx, instanceID, user, models.UserSignedUpAction, "", nil); terr != nil {
				return terr
			}

			if terr = triggerEventHooks(ctx, tx, SignupEvent, user, instanceID, config); terr != nil {
				return terr
			}
			if terr = user.Confirm(tx); terr != nil {
				return terr
			}
		} else {
			if terr = models.NewAuditLogEntry(tx, instanceID, user, models.LoginAction, "", nil); terr != nil {
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
		if terr = models.NewAuditLogEntry(tx, instanceID, user, models.UserSignedUpAction, "", nil); terr != nil {
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

		if terr = models.NewAuditLogEntry(tx, instanceID, user, models.UserModifiedAction, "", nil); terr != nil {
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

func (a *API) verifyEmailLink(ctx context.Context, conn *storage.Connection, params *VerifyParams, aud string) (*models.User, error) {
	config := getConfig(ctx)

	var user *models.User
	var err error

	switch params.Type {
	case signupVerification, inviteVerification:
		user, err = models.FindUserByConfirmationToken(conn, params.Token)
	case recoveryVerification, magicLinkVerification:
		user, err = models.FindUserByRecoveryToken(conn, params.Token)
	case emailChangeVerification:
		user, err = models.FindUserByEmailChangeToken(conn, params.Token)
	default:
		return nil, badRequestError("Invalid email verification type")
	}

	if err != nil {
		if models.IsNotFoundError(err) {
			return nil, expiredTokenError("Email link is invalid or has expired").WithInternalError(redirectWithQueryError)
		}
		return nil, internalServerError("Database error finding user from email link").WithInternalError(err)
	}

	if user.IsBanned() {
		return nil, unauthorizedError("Error confirming user").WithInternalError(redirectWithQueryError)
	}

	var isExpired bool
	switch params.Type {
	case signupVerification, inviteVerification:
		isExpired = isOtpExpired(user.ConfirmationSentAt, config.Mailer.OtpExp)
	case recoveryVerification, magicLinkVerification:
		isExpired = isOtpExpired(user.RecoverySentAt, config.Mailer.OtpExp)
	case emailChangeVerification:
		isExpired = isOtpExpired(user.EmailChangeSentAt, config.Mailer.OtpExp)
	}

	if isExpired {
		return nil, expiredTokenError("Email link is invalid or has expired").WithInternalError(redirectWithQueryError)
	}
	return user, nil
}

// verifyUserAndToken verifies the token associated to the user based on the verify type
func (a *API) verifyUserAndToken(ctx context.Context, conn *storage.Connection, params *VerifyParams, aud string) (*models.User, error) {
	instanceID := getInstanceID(ctx)
	config := getConfig(ctx)

	var user *models.User
	var err error
	var tokenHash string
	if isPhoneOtpVerification(params) {
		params.Phone, err = a.validatePhone(params.Phone)
		if err != nil {
			return nil, err
		}
		tokenHash = fmt.Sprintf("%x", sha256.Sum224([]byte(string(params.Phone)+params.Token)))
		switch params.Type {
		case phoneChangeVerification:
			user, err = models.FindUserByPhoneChangeAndAudience(conn, instanceID, params.Phone, aud)
		case smsVerification:
			user, err = models.FindUserByPhoneAndAudience(conn, instanceID, params.Phone, aud)
		default:
			return nil, badRequestError("Invalid sms verification type")
		}
	} else if isEmailOtpVerification(params) {
		if err := a.validateEmail(ctx, params.Email); err != nil {
			return nil, unprocessableEntityError("Invalid email format").WithInternalError(err)
		}
		tokenHash = fmt.Sprintf("%x", sha256.Sum224([]byte(string(params.Email)+params.Token)))
		switch params.Type {
		case emailChangeVerification:
			user, err = models.FindUserForEmailChange(conn, instanceID, params.Email, tokenHash, aud, config.Mailer.SecureEmailChangeEnabled)
		default:
			user, err = models.FindUserByEmailAndAudience(conn, instanceID, params.Email, aud)
		}
	} else {
		return nil, badRequestError("Only an email address or phone number should be provided on verify")
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
	switch params.Type {
	case signupVerification, inviteVerification:
		// TODO(km): remove when old token format is deprecated
		// the new token format is represented by a MD5 hash which is 32 characters (128 bits) long
		// anything shorter than 32 characters can safely be assumed to be using the old token format
		if len(user.ConfirmationToken) < sum224HashLength {
			tokenHash = params.Token
		}
		isValid = isOtpValid(tokenHash, user.ConfirmationToken, user.ConfirmationSentAt, config.Mailer.OtpExp)
	case recoveryVerification, magicLinkVerification:
		// TODO(km): remove when old token format is deprecated
		if len(user.RecoveryToken) < sum224HashLength {
			tokenHash = params.Token
		}
		isValid = isOtpValid(tokenHash, user.RecoveryToken, user.RecoverySentAt, config.Mailer.OtpExp)
	case emailChangeVerification:
		// TODO(km): remove when old token format is deprecated
		if len(user.EmailChangeTokenCurrent) < sum224HashLength && len(user.EmailChangeTokenNew) < sum224HashLength {
			tokenHash = params.Token
		}
		isValid = isOtpValid(tokenHash, user.EmailChangeTokenCurrent, user.EmailChangeSentAt, config.Mailer.OtpExp) ||
			isOtpValid(tokenHash, user.EmailChangeTokenNew, user.EmailChangeSentAt, config.Mailer.OtpExp)
	case phoneChangeVerification:
		// TODO(km): remove when old token format is deprecated
		if len(user.PhoneChangeToken) < sum224HashLength {
			tokenHash = params.Token
		}
		isValid = isOtpValid(tokenHash, user.PhoneChangeToken, user.PhoneChangeSentAt, config.Sms.OtpExp)
	case smsVerification:
		// TODO(km): remove when old token format is deprecated
		if len(user.ConfirmationToken) < sum224HashLength {
			tokenHash = params.Token
		}
		isValid = isOtpValid(tokenHash, user.ConfirmationToken, user.ConfirmationSentAt, config.Sms.OtpExp)
	}

	if !isValid || err != nil {
		return nil, expiredTokenError("Token has expired or is invalid").WithInternalError(redirectWithQueryError)
	}
	return user, nil
}

// isOtpValid checks the actual otp sent against the expected otp and ensures that it's within the valid window
func isOtpValid(actual, expected string, sentAt *time.Time, otpExp uint) bool {
	if expected == "" || sentAt == nil {
		return false
	}
	return !isOtpExpired(sentAt, otpExp) && (actual == expected)
}

func isOtpExpired(sentAt *time.Time, otpExp uint) bool {
	return time.Now().After(sentAt.Add(time.Second * time.Duration(otpExp)))
}

// isPhoneOtpVerification checks if the verification came from a phone otp
func isPhoneOtpVerification(params *VerifyParams) bool {
	return params.Phone != "" && params.Email == ""
}

// isEmailOtpVerification checks if the verification came from an email otp
func isEmailOtpVerification(params *VerifyParams) bool {
	return params.Phone == "" && params.Email != ""
}
