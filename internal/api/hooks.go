package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"time"

	"github.com/gofrs/uuid"
	jwt "github.com/golang-jwt/jwt"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/supabase/auth/internal/hooks"

	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/utilities"
)

type HookEvent string

const (
	headerHookSignature = "x-webhook-signature"
	defaultHookRetries  = 3
	gotrueIssuer        = "gotrue"
	ValidateEvent       = "validate"
	SignupEvent         = "signup"
	EmailChangeEvent    = "email_change"
	LoginEvent          = "login"
)

var defaultTimeout = time.Second * 5

type webhookClaims struct {
	jwt.StandardClaims
	SHA256 string `json:"sha256"`
}

type Webhook struct {
	*conf.WebhookConfig

	jwtSecret string
	claims    jwt.Claims
	payload   []byte
}

type WebhookResponse struct {
	AppMetaData  map[string]interface{} `json:"app_metadata,omitempty"`
	UserMetaData map[string]interface{} `json:"user_metadata,omitempty"`
}

func (w *Webhook) trigger() (io.ReadCloser, error) {
	timeout := defaultTimeout
	if w.TimeoutSec > 0 {
		timeout = time.Duration(w.TimeoutSec) * time.Second
	}

	if w.Retries == 0 {
		w.Retries = defaultHookRetries
	}

	hooklog := logrus.WithFields(logrus.Fields{
		"component":   "webhook",
		"url":         w.URL,
		"signed":      w.jwtSecret != "",
		"instance_id": uuid.Nil.String(),
	})
	client := http.Client{
		Timeout: timeout,
	}

	for i := 0; i < w.Retries; i++ {
		hooklog = hooklog.WithField("attempt", i+1)
		hooklog.Info("Starting to perform signup hook request")

		req, err := http.NewRequest(http.MethodPost, w.URL, bytes.NewBuffer(w.payload))
		if err != nil {
			return nil, internalServerError("Failed to make request object").WithInternalError(err)
		}
		req.Header.Set("Content-Type", "application/json")
		watcher, req := watchForConnection(req)

		if w.jwtSecret != "" {
			header, jwtErr := w.generateSignature()
			if jwtErr != nil {
				return nil, jwtErr
			}
			req.Header.Set(headerHookSignature, header)
		}

		start := time.Now()
		rsp, err := client.Do(req)
		if err != nil {
			if terr, ok := err.(net.Error); ok && terr.Timeout() {
				// timed out - try again?
				if i == w.Retries-1 {
					closeBody(rsp)
					return nil, httpError(http.StatusGatewayTimeout, "Failed to perform webhook in time frame (%v seconds)", timeout.Seconds())
				}
				hooklog.Info("Request timed out")
				continue
			} else if watcher.gotConn {
				closeBody(rsp)
				return nil, internalServerError("Failed to trigger webhook to %s", w.URL).WithInternalError(err)
			} else {
				closeBody(rsp)
				return nil, httpError(http.StatusBadGateway, "Failed to connect to %s", w.URL)
			}
		}
		dur := time.Since(start)
		rspLog := hooklog.WithFields(logrus.Fields{
			"status_code": rsp.StatusCode,
			"dur":         dur.Nanoseconds(),
		})
		switch rsp.StatusCode {
		case http.StatusOK, http.StatusNoContent, http.StatusAccepted:
			rspLog.Infof("Finished processing webhook in %s", dur)
			var body io.ReadCloser
			if rsp.ContentLength > 0 {
				body = rsp.Body
			}
			return body, nil
		default:
			rspLog.Infof("Bad response for webhook %d in %s", rsp.StatusCode, dur)
		}
	}

	hooklog.Infof("Failed to process webhook for %s after %d attempts", w.URL, w.Retries)
	return nil, unprocessableEntityError("Failed to handle signup webhook")
}

func (w *Webhook) generateSignature() (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, w.claims)
	tokenString, err := token.SignedString([]byte(w.jwtSecret))
	if err != nil {
		return "", internalServerError("Failed build signing string").WithInternalError(err)
	}
	return tokenString, nil
}

func closeBody(rsp *http.Response) {
	if rsp != nil && rsp.Body != nil {
		if err := rsp.Body.Close(); err != nil {
			logrus.WithError(err).Warn("body close in hooks failed")
		}
	}
}

func triggerEventHooks(ctx context.Context, conn *storage.Connection, event HookEvent, user *models.User, config *conf.GlobalConfiguration) error {
	if config.Webhook.URL != "" {
		hookURL, err := url.Parse(config.Webhook.URL)
		if err != nil {
			return errors.Wrapf(err, "Failed to parse Webhook URL")
		}
		if !config.Webhook.HasEvent(string(event)) {
			return nil
		}
		return triggerHook(ctx, hookURL, config.Webhook.Secret, conn, event, user, config)
	}

	fun := getFunctionHooks(ctx)
	if fun == nil {
		return nil
	}

	for _, eventHookURL := range fun[string(event)] {
		hookURL, err := url.Parse(eventHookURL)
		if err != nil {
			return errors.Wrapf(err, "Failed to parse Event Function Hook URL")
		}
		err = triggerHook(ctx, hookURL, config.JWT.Secret, conn, event, user, config)
		if err != nil {
			return err
		}
	}
	return nil
}

func triggerHook(ctx context.Context, hookURL *url.URL, secret string, conn *storage.Connection, event HookEvent, user *models.User, config *conf.GlobalConfiguration) error {
	if !hookURL.IsAbs() {
		siteURL, err := url.Parse(config.SiteURL)
		if err != nil {
			return errors.Wrapf(err, "Failed to parse Site URL")
		}
		hookURL.Scheme = siteURL.Scheme
		hookURL.Host = siteURL.Host
		hookURL.User = siteURL.User
	}

	payload := struct {
		Event      HookEvent    `json:"event"`
		InstanceID uuid.UUID    `json:"instance_id,omitempty"`
		User       *models.User `json:"user"`
	}{
		Event:      event,
		InstanceID: uuid.Nil,
		User:       user,
	}
	data, err := json.Marshal(&payload)
	if err != nil {
		return internalServerError("Failed to serialize the data for signup webhook").WithInternalError(err)
	}

	sha, err := checksum(data)
	if err != nil {
		return internalServerError("Failed to checksum the data for signup webhook").WithInternalError(err)
	}

	claims := webhookClaims{
		StandardClaims: jwt.StandardClaims{
			IssuedAt: time.Now().Unix(),
			Subject:  uuid.Nil.String(),
			Issuer:   gotrueIssuer,
		},
		SHA256: sha,
	}

	w := Webhook{
		WebhookConfig: &config.Webhook,
		jwtSecret:     secret,
		claims:        claims,
		payload:       data,
	}

	w.URL = hookURL.String()

	body, err := w.trigger()
	if body != nil {
		defer utilities.SafeClose(body)
	}
	if err == nil && body != nil {
		webhookRsp := &WebhookResponse{}
		decoder := json.NewDecoder(body)
		if err = decoder.Decode(webhookRsp); err != nil {
			return internalServerError("Webhook returned malformed JSON: %v", err).WithInternalError(err)
		}
		return conn.Transaction(func(tx *storage.Connection) error {
			if webhookRsp.UserMetaData != nil {
				user.UserMetaData = nil
				if terr := user.UpdateUserMetaData(tx, webhookRsp.UserMetaData); terr != nil {
					return terr
				}
			}
			if webhookRsp.AppMetaData != nil {
				user.AppMetaData = nil
				if terr := user.UpdateAppMetaData(tx, webhookRsp.AppMetaData); terr != nil {
					return terr
				}
			}
			return nil
		})
	}
	return err
}

func watchForConnection(req *http.Request) (*connectionWatcher, *http.Request) {
	w := new(connectionWatcher)
	t := &httptrace.ClientTrace{
		GotConn: w.GotConn,
	}

	req = req.WithContext(httptrace.WithClientTrace(req.Context(), t))
	return w, req
}

func checksum(data []byte) (string, error) {
	sha := sha256.New()
	_, err := sha.Write(data)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(sha.Sum(nil)), nil
}

type connectionWatcher struct {
	gotConn bool
}

func (c *connectionWatcher) GotConn(_ httptrace.GotConnInfo) {
	c.gotConn = true
}

func (a *API) runHook(ctx context.Context, name string, input, output any) ([]byte, error) {
	db := a.db.WithContext(ctx)

	request, err := json.Marshal(input)
	if err != nil {
		panic(err)
	}

	var response []byte
	if err := db.Transaction(func(tx *storage.Connection) error {
		// We rely on Postgres timeouts to ensure the function doesn't overrun
		if terr := tx.RawQuery(fmt.Sprintf("set local statement_timeout TO '%d';", hooks.DefaultTimeout)).Exec(); terr != nil {
			return terr
		}

		if terr := tx.RawQuery(fmt.Sprintf("select %s(?);", name), request).First(&response); terr != nil {
			return terr
		}

		// reset the timeout
		if terr := tx.RawQuery("set local statement_timeout TO default;").Exec(); terr != nil {
			return terr
		}

		return nil
	}); err != nil {
		return nil, err
	}

	if err := json.Unmarshal(response, output); err != nil {
		return response, err
	}

	return response, nil
}

func (a *API) invokeHook(ctx context.Context, input, output any) error {
	config := a.config
	switch input.(type) {
	case *hooks.MFAVerificationAttemptInput:
		hookOutput, ok := output.(*hooks.MFAVerificationAttemptOutput)
		if !ok {
			panic("output should be *hooks.MFAVerificationAttemptOutput")
		}

		if _, err := a.runHook(ctx, config.Hook.MFAVerificationAttempt.HookName, input, output); err != nil {
			return internalServerError("Error invoking MFA verification hook.").WithInternalError(err)
		}

		if hookOutput.IsError() {
			httpCode := hookOutput.HookError.HTTPCode

			if httpCode == 0 {
				httpCode = http.StatusInternalServerError
			}

			httpError := &HTTPError{
				Code:    httpCode,
				Message: hookOutput.HookError.Message,
			}

			return httpError.WithInternalError(&hookOutput.HookError)
		}

		return nil
	case *hooks.PasswordVerificationAttemptInput:
		hookOutput, ok := output.(*hooks.PasswordVerificationAttemptOutput)
		if !ok {
			panic("output should be *hooks.PasswordVerificationAttemptOutput")
		}

		if _, err := a.runHook(ctx, config.Hook.PasswordVerificationAttempt.HookName, input, output); err != nil {
			return internalServerError("Error invoking password verification hook.").WithInternalError(err)
		}

		if hookOutput.IsError() {
			httpCode := hookOutput.HookError.HTTPCode

			if httpCode == 0 {
				httpCode = http.StatusInternalServerError
			}

			httpError := &HTTPError{
				Code:    httpCode,
				Message: hookOutput.HookError.Message,
			}

			return httpError.WithInternalError(&hookOutput.HookError)
		}

		return nil
	case *hooks.CustomAccessTokenInput:
		hookOutput, ok := output.(*hooks.CustomAccessTokenOutput)
		if !ok {
			panic("output should be *hooks.CustomAccessTokenOutput")
		}

		if _, err := a.runHook(ctx, config.Hook.CustomAccessToken.HookName, input, output); err != nil {
			return internalServerError("Error invoking access token hook.").WithInternalError(err)
		}

		if hookOutput.IsError() {
			httpCode := hookOutput.HookError.HTTPCode

			if httpCode == 0 {
				httpCode = http.StatusInternalServerError
			}

			httpError := &HTTPError{
				Code:    httpCode,
				Message: hookOutput.HookError.Message,
			}

			return httpError.WithInternalError(&hookOutput.HookError)
		}
		if err := validateTokenClaims(hookOutput.Claims); err != nil {
			httpCode := hookOutput.HookError.HTTPCode

			if httpCode == 0 {
				httpCode = http.StatusInternalServerError
			}

			httpError := &HTTPError{
				Code:    httpCode,
				Message: err.Error(),
			}

			return httpError
		}
		return nil

	default:
		panic("unknown hook input type")
	}
}
