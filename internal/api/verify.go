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

	"github.com/sethvargo/go-password/password"
	"github.com/supabase/gotrue/internal/models"
	"github.com/supabase/gotrue/internal/observability"
	"github.com/supabase/gotrue/internal/storage"
)

var (
	// indicates that a user should be redirected due to an error
	errRedirectWithQuery = errors.New("redirect user")
)

const (
	signupVerification      = "signup"
	recoveryVerification    = "recovery"
	inviteVerification      = "invite"
	magicLinkVerification   = "magiclink"
	emailChangeVerification = "email_change"
	smsVerification         = "sms"
	phoneChangeVerification = "phone_change"
	// includes signupVerification and magicLinkVerification
	emailOTPVerification = "email"
)

const (
	zeroConfirmation int = iota
	singleConfirmation
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

func (p *VerifyParams) Validate() error {
	if p.Token == "" {
		return badRequestError("Verify requires a token")
	}

	if p.Type == "" {
		return badRequestError("Verify requires a verification type")
	}
	return nil
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
	db := a.db.WithContext(ctx)
	config := a.config
	params := &VerifyParams{}
	params.Token = r.FormValue("token")
	params.Type = r.FormValue("type")
	params.RedirectTo = a.getRedirectURLOrReferrer(r, r.FormValue("redirect_to"))

	var (
		user        *models.User
		grantParams models.GrantParams
		err         error
		token       *AccessTokenResponse
		authCode    string
	)
	var flowType models.FlowType
	var authenticationMethod models.AuthenticationMethod
	if strings.HasPrefix(params.Token, PKCEPrefix) {
		flowType = models.PKCEFlow
		authenticationMethod, err = models.ParseAuthenticationMethod(params.Type)
		if err != nil {
			return err
		}
	} else {
		flowType = models.ImplicitFlow
	}
	if err := params.Validate(); err != nil {
		return err
	}

	err = db.Transaction(func(tx *storage.Connection) error {
		var terr error

		params.Token = strings.ReplaceAll(params.Token, "-", "")
		aud := a.requestAud(ctx, r)
		user, terr = a.verifyEmailLink(ctx, tx, params, aud, flowType)
		if terr != nil {
			return terr
		}
		switch params.Type {
		case signupVerification, inviteVerification:
			user, terr = a.signupVerify(r, ctx, tx, user)
		case recoveryVerification, magicLinkVerification:
			user, terr = a.recoverVerify(r, ctx, tx, user)
		case emailChangeVerification:
			user, terr = a.emailChangeVerify(r, ctx, tx, params, user)
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
		if isImplicitFlow(flowType) {
			token, terr = a.issueRefreshToken(ctx, tx, user, models.OTP, grantParams)

			if terr != nil {
				return terr
			}

			if terr = a.setCookieTokens(config, token, false, w); terr != nil {
				return internalServerError("Failed to set JWT cookie. %s", terr)
			}
		} else if isPKCEFlow(flowType) {
			if authCode, terr = issueAuthCode(tx, user, a.config.External.FlowStateExpiryDuration, authenticationMethod); terr != nil {
				return badRequestError("No associated flow state found. %s", terr)
			}
		}
		return nil
	})

	if err != nil {
		var herr *HTTPError
		if errors.As(err, &herr) {
			rurl := a.prepErrorRedirectURL(herr, w, r, params.RedirectTo)
			http.Redirect(w, r, rurl, http.StatusSeeOther)
			return nil
		}
	}
	rurl := params.RedirectTo
	if isImplicitFlow(flowType) && token != nil {
		q := url.Values{}
		q.Set("type", params.Type)
		rurl = token.AsRedirectURL(rurl, q)
	} else if isPKCEFlow(flowType) {
		rurl, err = a.prepPKCERedirectURL(rurl, authCode)
		if err != nil {
			return err
		}
	}
	http.Redirect(w, r, rurl, http.StatusSeeOther)
	return nil
}

func (a *API) verifyPost(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	config := a.config
	params := &VerifyParams{}

	body, err := getBodyBytes(r)
	if err != nil {
		return badRequestError("Could not read body").WithInternalError(err)
	}

	if err := json.Unmarshal(body, params); err != nil {
		return badRequestError("Could not read verification params: %v", err)
	}

	if err := params.Validate(); err != nil {
		return err
	}

	params.Token = strings.ReplaceAll(params.Token, "-", "")

	var (
		user        *models.User
		grantParams models.GrantParams
		token       *AccessTokenResponse
	)

	err = db.Transaction(func(tx *storage.Connection) error {
		var terr error
		aud := a.requestAud(ctx, r)
		user, terr = a.verifyUserAndToken(ctx, tx, params, aud)
		if terr != nil {
			return terr
		}

		switch params.Type {
		case signupVerification, inviteVerification:
			user, terr = a.signupVerify(r, ctx, tx, user)
		case recoveryVerification, magicLinkVerification:
			user, terr = a.recoverVerify(r, ctx, tx, user)
		case emailChangeVerification:
			user, terr = a.emailChangeVerify(r, ctx, tx, params, user)
			if user == nil && terr == nil {
				return sendJSON(w, http.StatusOK, map[string]string{
					"msg":  singleConfirmationAccepted,
					"code": strconv.Itoa(http.StatusOK),
				})
			}
		case smsVerification, phoneChangeVerification:
			user, terr = a.smsVerify(r, ctx, tx, user, params.Type)
		default:
			return unprocessableEntityError("Unsupported verification type")
		}

		if terr != nil {
			return terr
		}
		token, terr = a.issueRefreshToken(ctx, tx, user, models.OTP, grantParams)
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

func (a *API) signupVerify(r *http.Request, ctx context.Context, conn *storage.Connection, user *models.User) (*models.User, error) {
	config := a.config

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

		if terr = models.NewAuditLogEntry(r, tx, user, models.UserSignedUpAction, "", nil); terr != nil {
			return terr
		}

		if terr = triggerEventHooks(ctx, tx, SignupEvent, user, config); terr != nil {
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

func (a *API) recoverVerify(r *http.Request, ctx context.Context, conn *storage.Connection, user *models.User) (*models.User, error) {
	config := a.config

	err := conn.Transaction(func(tx *storage.Connection) error {
		var terr error
		if terr = user.Recover(tx); terr != nil {
			return terr
		}
		if !user.IsConfirmed() {
			if terr = models.NewAuditLogEntry(r, tx, user, models.UserSignedUpAction, "", nil); terr != nil {
				return terr
			}

			if terr = triggerEventHooks(ctx, tx, SignupEvent, user, config); terr != nil {
				return terr
			}
			if terr = user.Confirm(tx); terr != nil {
				return terr
			}
		} else {
			if terr = models.NewAuditLogEntry(r, tx, user, models.LoginAction, "", nil); terr != nil {
				return terr
			}
			if terr = triggerEventHooks(ctx, tx, LoginEvent, user, config); terr != nil {
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

func (a *API) smsVerify(r *http.Request, ctx context.Context, conn *storage.Connection, user *models.User, otpType string) (*models.User, error) {
	config := a.config

	err := conn.Transaction(func(tx *storage.Connection) error {
		var terr error
		if terr = models.NewAuditLogEntry(r, tx, user, models.UserSignedUpAction, "", nil); terr != nil {
			return terr
		}

		if terr = triggerEventHooks(ctx, tx, SignupEvent, user, config); terr != nil {
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

func (a *API) prepErrorRedirectURL(err *HTTPError, w http.ResponseWriter, r *http.Request, rurl string) string {
	q := url.Values{}
	log := observability.GetLogEntry(r)
	errorID := getRequestID(r.Context())
	err.ErrorID = errorID
	log.WithError(err.Cause()).Info(err.Error())
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

func (a *API) prepPKCERedirectURL(rurl, code string) (string, error) {
	u, err := url.Parse(rurl)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("code", code)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (a *API) emailChangeVerify(r *http.Request, ctx context.Context, conn *storage.Connection, params *VerifyParams, user *models.User) (*models.User, error) {
	config := a.config

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

	// one email is confirmed at this point if GOTRUE_MAILER_SECURE_EMAIL_CHANGE_ENABLED is enabled
	err := conn.Transaction(func(tx *storage.Connection) error {
		var terr error

		if terr = models.NewAuditLogEntry(r, tx, user, models.UserModifiedAction, "", nil); terr != nil {
			return terr
		}

		if terr = triggerEventHooks(ctx, tx, EmailChangeEvent, user, config); terr != nil {
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

func (a *API) verifyEmailLink(ctx context.Context, conn *storage.Connection, params *VerifyParams, aud string, flowType models.FlowType) (*models.User, error) {
	config := a.config

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
			return nil, expiredTokenError("Email link is invalid or has expired").WithInternalError(errRedirectWithQuery)
		}
		return nil, internalServerError("Database error finding user from email link").WithInternalError(err)
	}

	if user.IsBanned() {
		return nil, unauthorizedError("Error confirming user").WithInternalError(errRedirectWithQuery)
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
		return nil, expiredTokenError("Email link is invalid or has expired").WithInternalError(errRedirectWithQuery)
	}

	return user, nil
}

// verifyUserAndToken verifies the token associated to the user based on the verify type
func (a *API) verifyUserAndToken(ctx context.Context, conn *storage.Connection, params *VerifyParams, aud string) (*models.User, error) {
	config := a.config

	var user *models.User
	var err error
	var tokenHash string

	if isPhoneOtpVerification(params) {
		params.Phone, err = validatePhone(params.Phone)
		if err != nil {
			return nil, err
		}
		tokenHash = fmt.Sprintf("%x", sha256.Sum224([]byte(string(params.Phone)+params.Token)))
		switch params.Type {
		case phoneChangeVerification:
			user, err = models.FindUserByPhoneChangeAndAudience(conn, params.Phone, aud)
		case smsVerification:
			user, err = models.FindUserByPhoneAndAudience(conn, params.Phone, aud)
		default:
			return nil, badRequestError("Invalid sms verification type")
		}
	} else if isEmailOtpVerification(params) {
		params.Email, err = validateEmail(params.Email)
		if err != nil {
			return nil, unprocessableEntityError("Invalid email format").WithInternalError(err)
		}
		tokenHash = fmt.Sprintf("%x", sha256.Sum224([]byte(string(params.Email)+params.Token)))
		switch params.Type {
		case emailChangeVerification:
			user, err = models.FindUserForEmailChange(conn, params.Email, tokenHash, aud, config.Mailer.SecureEmailChangeEnabled)
		default:
			user, err = models.FindUserByEmailAndAudience(conn, params.Email, aud)
		}
	} else {
		return nil, badRequestError("Only an email address or phone number should be provided on verify")
	}

	if err != nil {
		if models.IsNotFoundError(err) {
			return nil, notFoundError(err.Error()).WithInternalError(errRedirectWithQuery)
		}
		return nil, internalServerError("Database error finding user").WithInternalError(err)
	}

	if user.IsBanned() {
		return nil, unauthorizedError("Error confirming user").WithInternalError(errRedirectWithQuery)
	}

	var isValid bool
	switch params.Type {
	case emailOTPVerification:
		// if the type is emailOTPVerification, we'll check both the confirmation_token and recovery_token columns
		if isOtpValid(tokenHash, user.ConfirmationToken, user.ConfirmationSentAt, config.Mailer.OtpExp) {
			isValid = true
			params.Type = signupVerification
		} else if isOtpValid(tokenHash, user.RecoveryToken, user.RecoverySentAt, config.Mailer.OtpExp) {
			isValid = true
			params.Type = magicLinkVerification
		} else {
			isValid = false
		}
	case signupVerification, inviteVerification:
		isValid = isOtpValid(tokenHash, user.ConfirmationToken, user.ConfirmationSentAt, config.Mailer.OtpExp)
	case recoveryVerification, magicLinkVerification:
		isValid = isOtpValid(tokenHash, user.RecoveryToken, user.RecoverySentAt, config.Mailer.OtpExp)
	case emailChangeVerification:
		isValid = isOtpValid(tokenHash, user.EmailChangeTokenCurrent, user.EmailChangeSentAt, config.Mailer.OtpExp) ||
			isOtpValid(tokenHash, user.EmailChangeTokenNew, user.EmailChangeSentAt, config.Mailer.OtpExp)
	case phoneChangeVerification:
		isValid = isOtpValid(tokenHash, user.PhoneChangeToken, user.PhoneChangeSentAt, config.Sms.OtpExp)
	case smsVerification:
		isValid = isOtpValid(tokenHash, user.ConfirmationToken, user.ConfirmationSentAt, config.Sms.OtpExp)
	}

	if !isValid || err != nil {
		return nil, expiredTokenError("Token has expired or is invalid").WithInternalError(errRedirectWithQuery)
	}
	return user, nil
}

// isOtpValid checks the actual otp sent against the expected otp and ensures that it's within the valid window
func isOtpValid(actual, expected string, sentAt *time.Time, otpExp uint) bool {
	if expected == "" || sentAt == nil {
		return false
	}
	return !isOtpExpired(sentAt, otpExp) && ((actual == expected) || ("pkce_"+actual == expected))
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
