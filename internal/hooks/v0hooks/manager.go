package v0hooks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/sirupsen/logrus"
	standardwebhooks "github.com/standard-webhooks/standard-webhooks/libraries/go"
	"github.com/xeipuuv/gojsonschema"

	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/observability"
	"github.com/supabase/auth/internal/storage"
)

const (
	DefaultHTTPHookTimeout  = 5 * time.Second
	DefaultHTTPHookRetries  = 3
	HTTPHookBackoffDuration = 2 * time.Second
	PayloadLimit            = 200 * 1024 // 200KB
)

type Manager struct {
	db     *storage.Connection
	config *conf.GlobalConfiguration
}

func NewManager(
	db *storage.Connection,
	config *conf.GlobalConfiguration,
) *Manager {
	return &Manager{
		db:     db,
		config: config,
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
	return o.runHTTPHook(r, hookConfig, input)
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
	var response []byte

	switch input.(type) {
	case *SendSMSInput:
		hookOutput, ok := output.(*SendSMSOutput)
		if !ok {
			panic("output should be *hooks.SendSMSOutput")
		}
		if response, err = o.runHook(r, conn, o.config.Hook.SendSMS, input, output); err != nil {
			return err
		}
		if err := json.Unmarshal(response, hookOutput); err != nil {
			return apierrors.NewInternalServerError("Error unmarshaling Send SMS output.").WithInternalError(err)
		}
		if hookOutput.IsError() {
			httpCode := hookOutput.HookError.HTTPCode

			if httpCode == 0 {
				httpCode = http.StatusInternalServerError
			}
			httpError := &apierrors.HTTPError{
				HTTPStatus: httpCode,
				Message:    hookOutput.HookError.Message,
			}
			return httpError.WithInternalError(&hookOutput.HookError)
		}
		return nil
	case *SendEmailInput:
		hookOutput, ok := output.(*SendEmailOutput)
		if !ok {
			panic("output should be *hooks.SendEmailOutput")
		}
		if response, err = o.runHook(r, conn, o.config.Hook.SendEmail, input, output); err != nil {
			return err
		}
		if err := json.Unmarshal(response, hookOutput); err != nil {
			return apierrors.NewInternalServerError("Error unmarshaling Send Email output.").WithInternalError(err)
		}
		if hookOutput.IsError() {
			httpCode := hookOutput.HookError.HTTPCode

			if httpCode == 0 {
				httpCode = http.StatusInternalServerError
			}

			httpError := &apierrors.HTTPError{
				HTTPStatus: httpCode,
				Message:    hookOutput.HookError.Message,
			}

			return httpError.WithInternalError(&hookOutput.HookError)
		}
		return nil
	case *MFAVerificationAttemptInput:
		hookOutput, ok := output.(*MFAVerificationAttemptOutput)
		if !ok {
			panic("output should be *hooks.MFAVerificationAttemptOutput")
		}
		if response, err = o.runHook(r, conn, o.config.Hook.MFAVerificationAttempt, input, output); err != nil {
			return err
		}
		if err := json.Unmarshal(response, hookOutput); err != nil {
			return apierrors.NewInternalServerError("Error unmarshaling MFA Verification Attempt output.").WithInternalError(err)
		}
		if hookOutput.IsError() {
			httpCode := hookOutput.HookError.HTTPCode

			if httpCode == 0 {
				httpCode = http.StatusInternalServerError
			}

			httpError := &apierrors.HTTPError{
				HTTPStatus: httpCode,
				Message:    hookOutput.HookError.Message,
			}

			return httpError.WithInternalError(&hookOutput.HookError)
		}
		return nil
	case *PasswordVerificationAttemptInput:
		hookOutput, ok := output.(*PasswordVerificationAttemptOutput)
		if !ok {
			panic("output should be *hooks.PasswordVerificationAttemptOutput")
		}

		if response, err = o.runHook(r, conn, o.config.Hook.PasswordVerificationAttempt, input, output); err != nil {
			return err
		}
		if err := json.Unmarshal(response, hookOutput); err != nil {
			return apierrors.NewInternalServerError("Error unmarshaling Password Verification Attempt output.").WithInternalError(err)
		}
		if hookOutput.IsError() {
			httpCode := hookOutput.HookError.HTTPCode

			if httpCode == 0 {
				httpCode = http.StatusInternalServerError
			}

			httpError := &apierrors.HTTPError{
				HTTPStatus: httpCode,
				Message:    hookOutput.HookError.Message,
			}

			return httpError.WithInternalError(&hookOutput.HookError)
		}

		return nil
	case *CustomAccessTokenInput:
		hookOutput, ok := output.(*CustomAccessTokenOutput)
		if !ok {
			panic("output should be *hooks.CustomAccessTokenOutput")
		}
		if response, err = o.runHook(r, conn, o.config.Hook.CustomAccessToken, input, output); err != nil {
			return err
		}
		if err := json.Unmarshal(response, hookOutput); err != nil {
			return apierrors.NewInternalServerError("Error unmarshaling Custom Access Token output.").WithInternalError(err)
		}

		if hookOutput.IsError() {
			httpCode := hookOutput.HookError.HTTPCode

			if httpCode == 0 {
				httpCode = http.StatusInternalServerError
			}

			httpError := &apierrors.HTTPError{
				HTTPStatus: httpCode,
				Message:    hookOutput.HookError.Message,
			}

			return httpError.WithInternalError(&hookOutput.HookError)
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
	return nil
}

func (o *Manager) runHook(
	r *http.Request,
	conn *storage.Connection,
	hookConfig conf.ExtensibilityPointConfiguration,
	input, output any,
) ([]byte, error) {
	ctx := r.Context()

	logEntry := observability.GetLogEntry(r)
	hookStart := time.Now()

	var response []byte
	var err error

	switch {
	case strings.HasPrefix(hookConfig.URI, "http:") || strings.HasPrefix(hookConfig.URI, "https:"):
		response, err = o.runHTTPHook(r, hookConfig, input)
	case strings.HasPrefix(hookConfig.URI, "pg-functions:"):
		response, err = o.runPostgresHook(ctx, conn, hookConfig, input, output)
	default:
		return nil, fmt.Errorf("unsupported protocol: %q only postgres hooks and HTTPS functions are supported at the moment", hookConfig.URI)
	}

	duration := time.Since(hookStart)

	if err != nil {
		logEntry.Entry.WithFields(logrus.Fields{
			"action":   "run_hook",
			"hook":     hookConfig.URI,
			"success":  false,
			"duration": duration.Microseconds(),
		}).WithError(err).Warn("Hook errored out")

		return nil, apierrors.NewInternalServerError("Error running hook URI: %v", hookConfig.URI).WithInternalError(err)
	}

	logEntry.Entry.WithFields(logrus.Fields{
		"action":   "run_hook",
		"hook":     hookConfig.URI,
		"success":  true,
		"duration": duration.Microseconds(),
	}).WithError(err).Info("Hook ran successfully")

	return response, nil
}

func (o *Manager) runPostgresHook(
	ctx context.Context,
	tx *storage.Connection,
	hookConfig conf.ExtensibilityPointConfiguration,
	input, output any,
) ([]byte, error) {
	db := o.db.WithContext(ctx)

	request, err := json.Marshal(input)
	if err != nil {
		panic(err)
	}

	var response []byte
	invokeHookFunc := func(tx *storage.Connection) error {
		// We rely on Postgres timeouts to ensure the function doesn't overrun
		if terr := tx.RawQuery(fmt.Sprintf("set local statement_timeout TO '%d';", DefaultTimeout)).Exec(); terr != nil {
			return terr
		}

		if terr := tx.RawQuery(fmt.Sprintf("select %s(?);", hookConfig.HookName), request).First(&response); terr != nil {
			return terr
		}

		// reset the timeout
		if terr := tx.RawQuery("set local statement_timeout TO default;").Exec(); terr != nil {
			return terr
		}

		return nil
	}

	if tx != nil {
		if err := invokeHookFunc(tx); err != nil {
			return nil, err
		}
	} else {
		if err := db.Transaction(invokeHookFunc); err != nil {
			return nil, err
		}
	}

	if err := json.Unmarshal(response, output); err != nil {
		return response, err
	}

	return response, nil
}

func (o *Manager) runHTTPHook(
	r *http.Request,
	hookConfig conf.ExtensibilityPointConfiguration,
	input any,
) ([]byte, error) {
	ctx := r.Context()
	client := http.Client{
		Timeout: DefaultHTTPHookTimeout,
	}
	ctx, cancel := context.WithTimeout(ctx, DefaultHTTPHookTimeout)
	defer cancel()

	log := observability.GetLogEntry(r).Entry
	requestURL := hookConfig.URI
	hookLog := log.WithFields(logrus.Fields{
		"component": "auth_hook",
		"url":       requestURL,
	})

	inputPayload, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	for i := 0; i < DefaultHTTPHookRetries; i++ {
		if i == 0 {
			hookLog.Debugf("invocation attempt: %d", i)
		} else {
			hookLog.Infof("invocation attempt: %d", i)
		}
		msgID := uuid.Must(uuid.NewV4())
		currentTime := time.Now()
		signatureList, err := generateSignatures(hookConfig.HTTPHookSecrets, msgID, currentTime, inputPayload)
		if err != nil {
			return nil, err
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, bytes.NewBuffer(inputPayload))
		if err != nil {
			panic("Failed to make request object")
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("webhook-id", msgID.String())
		req.Header.Set("webhook-timestamp", fmt.Sprintf("%d", currentTime.Unix()))
		req.Header.Set("webhook-signature", strings.Join(signatureList, ", "))
		// By default, Go Client sets encoding to gzip, which does not carry a content length header.
		req.Header.Set("Accept-Encoding", "identity")

		rsp, err := client.Do(req)
		if err != nil && errors.Is(err, context.DeadlineExceeded) {
			return nil, apierrors.NewUnprocessableEntityError(apierrors.ErrorCodeHookTimeout, fmt.Sprintf("Failed to reach hook within maximum time of %f seconds", DefaultHTTPHookTimeout.Seconds()))

		} else if err != nil {
			if terr, ok := err.(net.Error); ok && terr.Timeout() || i < DefaultHTTPHookRetries-1 {
				hookLog.Errorf("Request timed out for attempt %d with err %s", i, err)
				time.Sleep(HTTPHookBackoffDuration)
				continue
			} else if i == DefaultHTTPHookRetries-1 {
				return nil, apierrors.NewUnprocessableEntityError(apierrors.ErrorCodeHookTimeoutAfterRetry, "Failed to reach hook after maximum retries")
			} else {
				return nil, apierrors.NewInternalServerError("Failed to trigger auth hook, error making HTTP request").WithInternalError(err)
			}
		}

		defer rsp.Body.Close()

		switch rsp.StatusCode {
		case http.StatusOK, http.StatusNoContent, http.StatusAccepted:
			// Header.Get is case insensitive
			contentType := rsp.Header.Get("Content-Type")
			if contentType == "" {
				return nil, apierrors.NewBadRequestError(apierrors.ErrorCodeHookPayloadInvalidContentType, "Invalid Content-Type: Missing Content-Type header")
			}
			mediaType, _, err := mime.ParseMediaType(contentType)
			if err != nil {
				return nil, apierrors.NewBadRequestError(apierrors.ErrorCodeHookPayloadInvalidContentType, fmt.Sprintf("Invalid Content-Type header: %s", err.Error()))
			}
			if mediaType != "application/json" {
				return nil, apierrors.NewBadRequestError(apierrors.ErrorCodeHookPayloadInvalidContentType, "Invalid JSON response. Received content-type: "+contentType)
			}
			if rsp.Body == nil {
				return nil, nil
			}
			limitedReader := io.LimitedReader{R: rsp.Body, N: PayloadLimit}
			body, err := io.ReadAll(&limitedReader)
			if err != nil {
				return nil, err
			}
			if limitedReader.N <= 0 {
				// check if the response body still has excess bytes to be read
				if n, _ := rsp.Body.Read(make([]byte, 1)); n > 0 {
					return nil, apierrors.NewUnprocessableEntityError(apierrors.ErrorCodeHookPayloadOverSizeLimit, fmt.Sprintf("Payload size exceeded size limit of %d bytes", PayloadLimit))
				}
			}
			return body, nil
		case http.StatusTooManyRequests, http.StatusServiceUnavailable:
			retryAfterHeader := rsp.Header.Get("retry-after")
			// Check for truthy values to allow for flexibility to switch to time duration
			if retryAfterHeader != "" {
				continue
			}
			return nil, apierrors.NewInternalServerError("Service currently unavailable due to hook")
		case http.StatusBadRequest:
			return nil, apierrors.NewInternalServerError("Invalid payload sent to hook")
		case http.StatusUnauthorized:
			return nil, apierrors.NewInternalServerError("Hook requires authorization token")
		default:
			return nil, apierrors.NewInternalServerError("Unexpected status code returned from hook: %d", rsp.StatusCode)
		}
	}
	return nil, nil
}

func generateSignatures(secrets []string, msgID uuid.UUID, currentTime time.Time, inputPayload []byte) ([]string, error) {
	SymmetricSignaturePrefix := "v1,"
	// TODO(joel): Handle asymmetric case once library has been upgraded
	var signatureList []string
	for _, secret := range secrets {
		if strings.HasPrefix(secret, SymmetricSignaturePrefix) {
			trimmedSecret := strings.TrimPrefix(secret, SymmetricSignaturePrefix)
			wh, err := standardwebhooks.NewWebhook(trimmedSecret)
			if err != nil {
				return nil, err
			}
			signature, err := wh.Sign(msgID.String(), currentTime, inputPayload)
			if err != nil {
				return nil, err
			}
			signatureList = append(signatureList, signature)
		} else {
			return nil, errors.New("invalid signature format")
		}
	}
	return signatureList, nil
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
		return fmt.Errorf("output claims do not conform to the expected schema: \n%s", errorMessages)

	}

	return nil
}
