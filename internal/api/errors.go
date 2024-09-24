package api

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"runtime/debug"
	"time"

	"github.com/pkg/errors"
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

func oauthError(err string, description string) *OAuthError {
	return &OAuthError{Err: err, Description: description}
}

func badRequestError(errorCode ErrorCode, fmtString string, args ...interface{}) *HTTPError {
	return httpError(http.StatusBadRequest, errorCode, fmtString, args...)
}

func internalServerError(fmtString string, args ...interface{}) *HTTPError {
	return httpError(http.StatusInternalServerError, ErrorCodeUnexpectedFailure, fmtString, args...)
}

func notFoundError(errorCode ErrorCode, fmtString string, args ...interface{}) *HTTPError {
	return httpError(http.StatusNotFound, errorCode, fmtString, args...)
}

func forbiddenError(errorCode ErrorCode, fmtString string, args ...interface{}) *HTTPError {
	return httpError(http.StatusForbidden, errorCode, fmtString, args...)
}

func unprocessableEntityError(errorCode ErrorCode, fmtString string, args ...interface{}) *HTTPError {
	return httpError(http.StatusUnprocessableEntity, errorCode, fmtString, args...)
}

func tooManyRequestsError(errorCode ErrorCode, fmtString string, args ...interface{}) *HTTPError {
	return httpError(http.StatusTooManyRequests, errorCode, fmtString, args...)
}

func conflictError(fmtString string, args ...interface{}) *HTTPError {
	return httpError(http.StatusConflict, ErrorCodeConflict, fmtString, args...)
}

// HTTPError is an error with a message and an HTTP status code.
type HTTPError struct {
	HTTPStatus      int    `json:"code"`                 // do not rename the JSON tags!
	ErrorCode       string `json:"error_code,omitempty"` // do not rename the JSON tags!
	Message         string `json:"msg"`                  // do not rename the JSON tags!
	InternalError   error  `json:"-"`
	InternalMessage string `json:"-"`
	ErrorID         string `json:"error_id,omitempty"`
}

func (e *HTTPError) Error() string {
	if e.InternalMessage != "" {
		return e.InternalMessage
	}
	return fmt.Sprintf("%d: %s", e.HTTPStatus, e.Message)
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

func httpError(httpStatus int, errorCode ErrorCode, fmtString string, args ...interface{}) *HTTPError {
	return &HTTPError{
		HTTPStatus: httpStatus,
		ErrorCode:  errorCode,
		Message:    fmt.Sprintf(fmtString, args...),
	}
}

// Recoverer is a middleware that recovers from panics, logs the panic (and a
// backtrace), and returns a HTTP 500 (Internal Server Error) status if
// possible. Recoverer prints a request ID if one is provided.
func recoverer(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
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
					HTTPStatus: http.StatusInternalServerError,
					Message:    http.StatusText(http.StatusInternalServerError),
				}
				HandleResponseError(se, w, r)
			}
		}()
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

// ErrorCause is an error interface that contains the method Cause() for returning root cause errors
type ErrorCause interface {
	Cause() error
}

type HTTPErrorResponse20240101 struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
}

func HandleResponseError(err error, w http.ResponseWriter, r *http.Request) {
	log := observability.GetLogEntry(r).Entry
	errorID := utilities.GetRequestID(r.Context())

	apiVersion, averr := DetermineClosestAPIVersion(r.Header.Get(APIVersionHeaderName))
	if averr != nil {
		log.WithError(averr).Warn("Invalid version passed to " + APIVersionHeaderName + " header, defaulting to initial version")
	} else if apiVersion != APIVersionInitial {
		// Echo back the determined API version from the request
		w.Header().Set(APIVersionHeaderName, FormatAPIVersion(apiVersion))
	}

	switch e := err.(type) {
	case *WeakPasswordError:
		if apiVersion.Compare(APIVersion20240101) >= 0 {
			var output struct {
				HTTPErrorResponse20240101
				Payload struct {
					Reasons []string `json:"reasons,omitempty"`
				} `json:"weak_password,omitempty"`
			}

			output.Code = ErrorCodeWeakPassword
			output.Message = e.Message
			output.Payload.Reasons = e.Reasons

			if jsonErr := sendJSON(w, http.StatusUnprocessableEntity, output); jsonErr != nil && jsonErr != context.DeadlineExceeded {
				log.WithError(jsonErr).Warn("Failed to send JSON on ResponseWriter")
			}

		} else {
			var output struct {
				HTTPError
				Payload struct {
					Reasons []string `json:"reasons,omitempty"`
				} `json:"weak_password,omitempty"`
			}

			output.HTTPStatus = http.StatusUnprocessableEntity
			output.ErrorCode = ErrorCodeWeakPassword
			output.Message = e.Message
			output.Payload.Reasons = e.Reasons

			w.Header().Set("x-sb-error-code", output.ErrorCode)

			if jsonErr := sendJSON(w, output.HTTPStatus, output); jsonErr != nil && jsonErr != context.DeadlineExceeded {
				log.WithError(jsonErr).Warn("Failed to send JSON on ResponseWriter")
			}
		}

	case *HTTPError:
		switch {
		case e.HTTPStatus >= http.StatusInternalServerError:
			e.ErrorID = errorID
			// this will get us the stack trace too
			log.WithError(e.Cause()).Error(e.Error())
		case e.HTTPStatus == http.StatusTooManyRequests:
			log.WithError(e.Cause()).Warn(e.Error())
		default:
			log.WithError(e.Cause()).Info(e.Error())
		}

		if e.ErrorCode != "" {
			w.Header().Set("x-sb-error-code", e.ErrorCode)
		}

		if apiVersion.Compare(APIVersion20240101) >= 0 {
			resp := HTTPErrorResponse20240101{
				Code:    e.ErrorCode,
				Message: e.Message,
			}

			if resp.Code == "" {
				if e.HTTPStatus == http.StatusInternalServerError {
					resp.Code = ErrorCodeUnexpectedFailure
				} else {
					resp.Code = ErrorCodeUnknown
				}
			}

			if jsonErr := sendJSON(w, e.HTTPStatus, resp); jsonErr != nil && jsonErr != context.DeadlineExceeded {
				log.WithError(jsonErr).Warn("Failed to send JSON on ResponseWriter")
			}
		} else {
			if e.ErrorCode == "" {
				if e.HTTPStatus == http.StatusInternalServerError {
					e.ErrorCode = ErrorCodeUnexpectedFailure
				} else {
					e.ErrorCode = ErrorCodeUnknown
				}
			}

			// Provide better error messages for certain user-triggered Postgres errors.
			if pgErr := utilities.NewPostgresError(e.InternalError); pgErr != nil {
				if jsonErr := sendJSON(w, pgErr.HttpStatusCode, pgErr); jsonErr != nil && jsonErr != context.DeadlineExceeded {
					log.WithError(jsonErr).Warn("Failed to send JSON on ResponseWriter")
				}
				return
			}

			if jsonErr := sendJSON(w, e.HTTPStatus, e); jsonErr != nil && jsonErr != context.DeadlineExceeded {
				log.WithError(jsonErr).Warn("Failed to send JSON on ResponseWriter")
			}
		}

	case *OAuthError:
		log.WithError(e.Cause()).Info(e.Error())
		if jsonErr := sendJSON(w, http.StatusBadRequest, e); jsonErr != nil && jsonErr != context.DeadlineExceeded {
			log.WithError(jsonErr).Warn("Failed to send JSON on ResponseWriter")
		}

	case ErrorCause:
		HandleResponseError(e.Cause(), w, r)

	default:
		log.WithError(e).Errorf("Unhandled server error: %s", e.Error())

		if apiVersion.Compare(APIVersion20240101) >= 0 {
			resp := HTTPErrorResponse20240101{
				Code:    ErrorCodeUnexpectedFailure,
				Message: "Unexpected failure, please check server logs for more information",
			}

			if jsonErr := sendJSON(w, http.StatusInternalServerError, resp); jsonErr != nil && jsonErr != context.DeadlineExceeded {
				log.WithError(jsonErr).Warn("Failed to send JSON on ResponseWriter")
			}
		} else {
			httpError := HTTPError{
				HTTPStatus: http.StatusInternalServerError,
				ErrorCode:  ErrorCodeUnexpectedFailure,
				Message:    "Unexpected failure, please check server logs for more information",
			}

			if jsonErr := sendJSON(w, http.StatusInternalServerError, httpError); jsonErr != nil && jsonErr != context.DeadlineExceeded {
				log.WithError(jsonErr).Warn("Failed to send JSON on ResponseWriter")
			}
		}
	}
}

func generateFrequencyLimitErrorMessage(timeStamp *time.Time, maxFrequency time.Duration) string {
	now := time.Now()
	left := timeStamp.Add(maxFrequency).Sub(now) / time.Second
	return fmt.Sprintf("For security purposes, you can only request this after %d seconds.", left)
}
