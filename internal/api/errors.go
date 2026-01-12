package api

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"runtime/debug"
	"time"

	"github.com/pkg/errors"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/observability"
	"github.com/supabase/auth/internal/utilities"
)

// Common error messages during signup flow
var (
	DuplicateEmailMsg       = "A user with this email address has already been registered"
	DuplicatePhoneMsg       = "A user with this phone number has already been registered"
	UserExistsError   error = errors.New("user already exists")
)

const InvalidChannelError = "Invalid channel, supported values are 'sms' or 'whatsapp'. 'whatsapp' is only supported if Twilio or Twilio Verify is used as the provider."

var oauthErrorMap = map[int]string{
	http.StatusBadRequest:          "invalid_request",
	http.StatusUnauthorized:        "unauthorized_client",
	http.StatusForbidden:           "access_denied",
	http.StatusInternalServerError: "server_error",
	http.StatusServiceUnavailable:  "temporarily_unavailable",
}

// Type aliases while we slowly refactor api errors.
type (
	HTTPError  = apierrors.HTTPError
	OAuthError = apierrors.OAuthError
)

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
	Code    apierrors.ErrorCode `json:"code"`
	Message string              `json:"message"`
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

			output.Code = apierrors.ErrorCodeWeakPassword
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
			output.ErrorCode = apierrors.ErrorCodeWeakPassword
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
					resp.Code = apierrors.ErrorCodeUnexpectedFailure
				} else {
					resp.Code = apierrors.ErrorCodeUnknown
				}
			}

			if jsonErr := sendJSON(w, e.HTTPStatus, resp); jsonErr != nil && jsonErr != context.DeadlineExceeded {
				log.WithError(jsonErr).Warn("Failed to send JSON on ResponseWriter")
			}
		} else {
			if e.ErrorCode == "" {
				if e.HTTPStatus == http.StatusInternalServerError {
					e.ErrorCode = apierrors.ErrorCodeUnexpectedFailure
				} else {
					e.ErrorCode = apierrors.ErrorCodeUnknown
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
				Code:    apierrors.ErrorCodeUnexpectedFailure,
				Message: "Unexpected failure, please check server logs for more information",
			}

			if jsonErr := sendJSON(w, http.StatusInternalServerError, resp); jsonErr != nil && jsonErr != context.DeadlineExceeded {
				log.WithError(jsonErr).Warn("Failed to send JSON on ResponseWriter")
			}
		} else {
			httpError := HTTPError{
				HTTPStatus: http.StatusInternalServerError,
				ErrorCode:  apierrors.ErrorCodeUnexpectedFailure,
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
