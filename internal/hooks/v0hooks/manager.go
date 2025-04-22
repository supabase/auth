package v0hooks

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/xeipuuv/gojsonschema"

	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/hooks/v0hooks/v0http"
	"github.com/supabase/auth/internal/hooks/v0hooks/v0pgfunc"
	"github.com/supabase/auth/internal/observability"
	"github.com/supabase/auth/internal/storage"
)

type Manager struct {
	config   *conf.GlobalConfiguration
	v0http   *v0http.Dispatcher
	v0pgfunc *v0pgfunc.Dispatcher
}

func NewManager(
	config *conf.GlobalConfiguration,
	httpDr *v0http.Dispatcher,
	pgfuncDr *v0pgfunc.Dispatcher,
) *Manager {
	return &Manager{
		config:   config,
		v0http:   httpDr,
		v0pgfunc: pgfuncDr,
	}
}

func (o *Manager) InvokeHook(
	conn *storage.Connection,
	r *http.Request,
	input, output any,
) error {
	return o.invokeHook(conn, r, input, output)
}

func (o *Manager) RunHTTPHook(
	r *http.Request,
	hookConfig conf.ExtensibilityPointConfiguration,
	input any,
) ([]byte, error) {
	return o.v0http.RunHTTPHook(r.Context(), hookConfig, input)
}

// invokeHook invokes the hook code. conn can be nil, in which case a new
// transaction is opened. If calling invokeHook within a transaction, always
// pass the current transaction, as pool-exhaustion deadlocks are very easy to
// trigger.
func (o *Manager) invokeHook(
	conn *storage.Connection,
	r *http.Request,
	input, output any,
) error {
	var err error
	switch input.(type) {
	default:
		return apierrors.NewInternalServerError(
			"Unknown hook type %T.", input)

	case *SendSMSInput:
		hookOutput, ok := output.(*SendSMSOutput)
		if !ok {
			return apierrors.NewInternalServerError(
				"output should be *hooks.SendSMSOutput")
		}
		if err = o.runHook(r, conn, o.config.Hook.SendSMS, input, hookOutput); err != nil {
			return err
		}
		return checkError(hookOutput)

	case *SendEmailInput:
		hookOutput, ok := output.(*SendEmailOutput)
		if !ok {
			return apierrors.NewInternalServerError(
				"output should be *hooks.SendEmailOutput")
		}
		if err := o.runHook(r, conn, o.config.Hook.SendEmail, input, hookOutput); err != nil {
			return err
		}
		return checkError(hookOutput)

	case *MFAVerificationAttemptInput:
		hookOutput, ok := output.(*MFAVerificationAttemptOutput)
		if !ok {
			return apierrors.NewInternalServerError(
				"output should be *hooks.MFAVerificationAttemptOutput")
		}
		if err := o.runHook(r, conn, o.config.Hook.MFAVerificationAttempt, input, hookOutput); err != nil {
			return err
		}
		return checkError(hookOutput)

	case *PasswordVerificationAttemptInput:
		hookOutput, ok := output.(*PasswordVerificationAttemptOutput)
		if !ok {
			return apierrors.NewInternalServerError(
				"output should be *hooks.PasswordVerificationAttemptOutput")
		}
		if err := o.runHook(r, conn, o.config.Hook.PasswordVerificationAttempt, input, hookOutput); err != nil {
			return err
		}
		return checkError(hookOutput)

	case *CustomAccessTokenInput:
		hookOutput, ok := output.(*CustomAccessTokenOutput)
		if !ok {
			return apierrors.NewInternalServerError(
				"output should be *hooks.CustomAccessTokenOutput")
		}
		if err := o.runHook(r, conn, o.config.Hook.CustomAccessToken, input, hookOutput); err != nil {
			return err
		}
		if err := checkError(hookOutput); err != nil {
			return err
		}
		if err := validateTokenClaims(hookOutput.Claims); err != nil {
			httpCode := hookOutput.HookError.HTTPCode

			if httpCode == 0 {
				httpCode = http.StatusInternalServerError
			}
			httpError := &apierrors.HTTPError{
				HTTPStatus: httpCode,
				Message:    err.Error(),
			}
			return httpError
		}
		return nil
	}
}

func (o *Manager) runHook(
	r *http.Request,
	conn *storage.Connection,
	hookConfig conf.ExtensibilityPointConfiguration,
	input, output any,
) error {
	ctx := r.Context()

	logEntry := observability.GetLogEntry(r)
	hookStart := time.Now()

	var err error
	switch {
	case strings.HasPrefix(hookConfig.URI, "http:") ||
		strings.HasPrefix(hookConfig.URI, "https:"):
		err = o.v0http.Dispatch(ctx, hookConfig, input, output)

	case strings.HasPrefix(hookConfig.URI, "pg-functions:"):
		err = o.v0pgfunc.Dispatch(ctx, hookConfig, conn, input, output)

	default:
		return fmt.Errorf(
			"unsupported protocol: %q only postgres hooks and HTTPS functions"+
				" are supported at the moment", hookConfig.URI)
	}

	duration := time.Since(hookStart)

	if err != nil {
		logEntry.Entry.WithFields(logrus.Fields{
			"action":   "run_hook",
			"hook":     hookConfig.URI,
			"success":  false,
			"duration": duration.Microseconds(),
		}).WithError(err).Warn("Hook errored out")

		return apierrors.NewInternalServerError(
			"Error running hook URI: %v", hookConfig.URI).WithInternalError(err)
	}

	logEntry.Entry.WithFields(logrus.Fields{
		"action":   "run_hook",
		"hook":     hookConfig.URI,
		"success":  true,
		"duration": duration.Microseconds(),
	}).WithError(err).Info("Hook ran successfully")

	return nil
}

func checkError(
	hookOutput HookOutput,
) error {
	if hookOutput.IsError() {
		he := hookOutput.GetHookError()
		httpCode := he.HTTPCode

		if httpCode == 0 {
			httpCode = http.StatusInternalServerError
		}

		httpError := &apierrors.HTTPError{
			HTTPStatus: httpCode,
			Message:    he.Message,
		}
		return httpError.WithInternalError(&he)
	}
	return nil
}

func validateTokenClaims(outputClaims map[string]interface{}) error {
	schemaLoader := gojsonschema.NewStringLoader(MinimumViableTokenSchema)

	documentLoader := gojsonschema.NewGoLoader(outputClaims)

	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		return err
	}

	if !result.Valid() {
		var errorMessages string

		for _, desc := range result.Errors() {
			errorMessages += fmt.Sprintf("- %s\n", desc)
			fmt.Printf("- %s\n", desc)
		}
		return fmt.Errorf(
			"output claims do not conform to the expected schema: \n%s", errorMessages)

	}

	return nil
}
