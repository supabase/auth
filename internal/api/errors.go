package api

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"runtime/debug"

	"github.com/pkg/errors"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/observability"
	"github.com/supabase/auth/internal/utilities"
)

// Common error messages during signup flow
var (
	DuplicateEmailMsg       = "A user with this email address has already been registered"
	DuplicatePhoneMsg       = "A user with this phone number has already been registered"
	UserExistsError   error = errors.New("user already exists")
)

const InvalidChannelError = "Invalid channel, supported values are 'sms' or 'whatsapp'"

var oauthErrorMap = map[int]string{
	http.StatusBadRequest:          "invalid_request",
	http.StatusUnauthorized:        "unauthorized_client",
	http.StatusForbidden:           "access_denied",
	http.StatusInternalServerError: "server_error",
	http.StatusServiceUnavailable:  "temporarily_unavailable",
}

// OAuthError is the JSON handler for OAuth2 error responses
type OAuthError struct {
	Err             string `json:"error"`
	Description     string `json:"error_description,omitempty"`
	InternalError   error  `json:"-"`
	InternalMessage string `json:"-"`
}

func (e *OAuthError) Error() string {
	if e.InternalMessage != "" {
		return e.InternalMessage
	}
	return fmt.Sprintf("%s: %s", e.Err, e.Description)
}

// WithInternalError adds internal error information to the error
func (e *OAuthError) WithInternalError(err error) *OAuthError {
	e.InternalError = err
	return e
}

// WithInternalMessage adds internal message information to the error
func (e *OAuthError) WithInternalMessage(fmtString string, args ...interface{}) *OAuthError {
	e.InternalMessage = fmt.Sprintf(fmtString, args...)
	return e
}

// Cause returns the root cause error
func (e *OAuthError) Cause() error {
	if e.InternalError != nil {
		return e.InternalError
	}
	return e
}

func invalidSignupError(config *conf.GlobalConfiguration) *HTTPError {
	var msg string
	if config.External.Email.Enabled && config.External.Phone.Enabled {
		msg = "To signup, please provide your email or phone number"
	} else if config.External.Email.Enabled {
		msg = "To signup, please provide your email"
	} else if config.External.Phone.Enabled {
		msg = "To signup, please provide your phone number"
	} else {
		// 3rd party OAuth signups
		msg = "To signup, please provide required fields"
	}
	return unprocessableEntityError(msg)
}

func oauthError(err string, description string) *OAuthError {
	return &OAuthError{Err: err, Description: description}
}

func badRequestError(fmtString string, args ...interface{}) *HTTPError {
	return httpError(http.StatusBadRequest, fmtString, args...)
}

func internalServerError(fmtString string, args ...interface{}) *HTTPError {
	return httpError(http.StatusInternalServerError, fmtString, args...)
}

func notFoundError(fmtString string, args ...interface{}) *HTTPError {
	return httpError(http.StatusNotFound, fmtString, args...)
}

func expiredTokenError(fmtString string, args ...interface{}) *HTTPError {
	return httpError(http.StatusUnauthorized, fmtString, args...)
}

func unauthorizedError(fmtString string, args ...interface{}) *HTTPError {
	return httpError(http.StatusUnauthorized, fmtString, args...)
}

func forbiddenError(fmtString string, args ...interface{}) *HTTPError {
	return httpError(http.StatusForbidden, fmtString, args...)
}

func unprocessableEntityError(fmtString string, args ...interface{}) *HTTPError {
	return httpError(http.StatusUnprocessableEntity, fmtString, args...)
}

func tooManyRequestsError(fmtString string, args ...interface{}) *HTTPError {
	return httpError(http.StatusTooManyRequests, fmtString, args...)
}

func conflictError(fmtString string, args ...interface{}) *HTTPError {
	return httpError(http.StatusConflict, fmtString, args...)
}

// HTTPError is an error with a message and an HTTP status code.
type HTTPError struct {
	Code            int    `json:"code"`
	Message         string `json:"msg"`
	InternalError   error  `json:"-"`
	InternalMessage string `json:"-"`
	ErrorID         string `json:"error_id,omitempty"`
}

func (e *HTTPError) Error() string {
	if e.InternalMessage != "" {
		return e.InternalMessage
	}
	return fmt.Sprintf("%d: %s", e.Code, e.Message)
}

func (e *HTTPError) Is(target error) bool {
	return e.Error() == target.Error()
}

// Cause returns the root cause error
func (e *HTTPError) Cause() error {
	if e.InternalError != nil {
		return e.InternalError
	}
	return e
}

// WithInternalError adds internal error information to the error
func (e *HTTPError) WithInternalError(err error) *HTTPError {
	e.InternalError = err
	return e
}

// WithInternalMessage adds internal message information to the error
func (e *HTTPError) WithInternalMessage(fmtString string, args ...interface{}) *HTTPError {
	e.InternalMessage = fmt.Sprintf(fmtString, args...)
	return e
}

func httpError(code int, fmtString string, args ...interface{}) *HTTPError {
	return &HTTPError{
		Code:    code,
		Message: fmt.Sprintf(fmtString, args...),
	}
}

// OTPError is a custom error struct for phone auth errors
type OTPError struct {
	Err             string `json:"error"`
	Description     string `json:"error_description,omitempty"`
	InternalError   error  `json:"-"`
	InternalMessage string `json:"-"`
}

func (e *OTPError) Error() string {
	if e.InternalMessage != "" {
		return e.InternalMessage
	}
	return fmt.Sprintf("%s: %s", e.Err, e.Description)
}

// WithInternalError adds internal error information to the error
func (e *OTPError) WithInternalError(err error) *OTPError {
	e.InternalError = err
	return e
}

// WithInternalMessage adds internal message information to the error
func (e *OTPError) WithInternalMessage(fmtString string, args ...interface{}) *OTPError {
	e.InternalMessage = fmt.Sprintf(fmtString, args...)
	return e
}

// Cause returns the root cause error
func (e *OTPError) Cause() error {
	if e.InternalError != nil {
		return e.InternalError
	}
	return e
}

func otpError(err string, description string) *OTPError {
	return &OTPError{Err: err, Description: description}
}

// Recoverer is a middleware that recovers from panics, logs the panic (and a
// backtrace), and returns a HTTP 500 (Internal Server Error) status if
// possible. Recoverer prints a request ID if one is provided.
func recoverer(w http.ResponseWriter, r *http.Request) (context.Context, error) {
	defer func() {
		if rvr := recover(); rvr != nil {

			logEntry := observability.GetLogEntry(r)
			if logEntry != nil {
				logEntry.Panic(rvr, debug.Stack())
			} else {
				fmt.Fprintf(os.Stderr, "Panic: %+v\n", rvr)
				debug.PrintStack()
			}

			se := &HTTPError{
				Code:    http.StatusInternalServerError,
				Message: http.StatusText(http.StatusInternalServerError),
			}
			handleError(se, w, r)
		}
	}()

	return nil, nil
}

// ErrorCause is an error interface that contains the method Cause() for returning root cause errors
type ErrorCause interface {
	Cause() error
}

func handleError(err error, w http.ResponseWriter, r *http.Request) {
	log := observability.GetLogEntry(r)
	errorID := getRequestID(r.Context())
	switch e := err.(type) {
	case *WeakPasswordError:
		var output struct {
			HTTPError
			Payload struct {
				Reasons []string `json:"reasons,omitempty"`
			} `json:"weak_password,omitempty"`
		}

		output.Code = http.StatusUnprocessableEntity
		output.Message = e.Message
		output.Payload.Reasons = e.Reasons

		if jsonErr := sendJSON(w, output.Code, output); jsonErr != nil {
			handleError(jsonErr, w, r)
		}

	case *HTTPError:
		if e.Code >= http.StatusInternalServerError {
			e.ErrorID = errorID
			// this will get us the stack trace too
			log.WithError(e.Cause()).Error(e.Error())
		} else {
			log.WithError(e.Cause()).Info(e.Error())
		}

		// Provide better error messages for certain user-triggered Postgres errors.
		if pgErr := utilities.NewPostgresError(e.InternalError); pgErr != nil {
			if jsonErr := sendJSON(w, pgErr.HttpStatusCode, pgErr); jsonErr != nil {
				handleError(jsonErr, w, r)
			}
			return
		}

		if jsonErr := sendJSON(w, e.Code, e); jsonErr != nil {
			handleError(jsonErr, w, r)
		}
	case *OAuthError:
		log.WithError(e.Cause()).Info(e.Error())
		if jsonErr := sendJSON(w, http.StatusBadRequest, e); jsonErr != nil {
			handleError(jsonErr, w, r)
		}
	case *OTPError:
		log.WithError(e.Cause()).Info(e.Error())
		if jsonErr := sendJSON(w, http.StatusBadRequest, e); jsonErr != nil {
			handleError(jsonErr, w, r)
		}
	case ErrorCause:
		handleError(e.Cause(), w, r)
	default:
		log.WithError(e).Errorf("Unhandled server error: %s", e.Error())
		// hide real error details from response to prevent info leaks
		w.WriteHeader(http.StatusInternalServerError)
		if _, writeErr := w.Write([]byte(`{"code":500,"msg":"Internal server error","error_id":"` + errorID + `"}`)); writeErr != nil {
			log.WithError(writeErr).Error("Error writing generic error message")
		}
	}
}
