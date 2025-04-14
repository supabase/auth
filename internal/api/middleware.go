package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/sirupsen/logrus"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/observability"
	"github.com/supabase/auth/internal/security"
	"github.com/supabase/auth/internal/utilities"

	"github.com/didip/tollbooth/v5"
	"github.com/didip/tollbooth/v5/limiter"
	jwt "github.com/golang-jwt/jwt/v5"
)

type FunctionHooks map[string][]string

type AuthMicroserviceClaims struct {
	jwt.RegisteredClaims
	SiteURL       string        `json:"site_url"`
	InstanceID    string        `json:"id"`
	FunctionHooks FunctionHooks `json:"function_hooks"`
}

func (f *FunctionHooks) UnmarshalJSON(b []byte) error {
	var raw map[string][]string
	err := json.Unmarshal(b, &raw)
	if err == nil {
		*f = FunctionHooks(raw)
		return nil
	}
	// If unmarshaling into map[string][]string fails, try legacy format.
	var legacy map[string]string
	err = json.Unmarshal(b, &legacy)
	if err != nil {
		return err
	}
	if *f == nil {
		*f = make(FunctionHooks)
	}
	for event, hook := range legacy {
		(*f)[event] = []string{hook}
	}
	return nil
}

var emailRateLimitCounter = observability.ObtainMetricCounter("gotrue_email_rate_limit_counter", "Number of times an email rate limit has been triggered")

func (a *API) performRateLimiting(lmt *limiter.Limiter, req *http.Request) error {
	if limitHeader := a.config.RateLimitHeader; limitHeader != "" {
		key := req.Header.Get(limitHeader)

		if key == "" {
			log := observability.GetLogEntry(req).Entry
			log.WithField("header", limitHeader).Warn("request does not have a value for the rate limiting header, rate limiting is not applied")
		} else {
			err := tollbooth.LimitByKeys(lmt, []string{key})
			if err != nil {
				return apierrors.NewTooManyRequestsError(apierrors.ErrorCodeOverRequestRateLimit, "Request rate limit reached")
			}
		}
	}

	return nil
}

func (a *API) limitHandler(lmt *limiter.Limiter) middlewareHandler {
	return func(w http.ResponseWriter, req *http.Request) (context.Context, error) {
		return req.Context(), a.performRateLimiting(lmt, req)
	}
}

func (a *API) requireAdminCredentials(w http.ResponseWriter, req *http.Request) (context.Context, error) {
	t, err := a.extractBearerToken(req)
	if err != nil || t == "" {
		return nil, err
	}

	ctx, err := a.parseJWTClaims(t, req)
	if err != nil {
		return nil, err
	}

	return a.requireAdmin(ctx)
}

func (a *API) requireEmailProvider(w http.ResponseWriter, req *http.Request) (context.Context, error) {
	ctx := req.Context()
	config := a.config

	if !config.External.Email.Enabled {
		return nil, apierrors.NewBadRequestError(apierrors.ErrorCodeEmailProviderDisabled, "Email logins are disabled")
	}

	return ctx, nil
}

func (a *API) verifyCaptcha(w http.ResponseWriter, req *http.Request) (context.Context, error) {
	ctx := req.Context()
	config := a.config

	if !config.Security.Captcha.Enabled {
		return ctx, nil
	}
	if _, err := a.requireAdminCredentials(w, req); err == nil {
		// skip captcha validation if authorization header contains an admin role
		return ctx, nil
	}
	if shouldIgnore := isIgnoreCaptchaRoute(req); shouldIgnore {
		return ctx, nil
	}

	body := &security.GotrueRequest{}
	if err := retrieveRequestParams(req, body); err != nil {
		return nil, err
	}

	verificationResult, err := security.VerifyRequest(body, utilities.GetIPAddress(req), strings.TrimSpace(config.Security.Captcha.Secret), config.Security.Captcha.Provider)
	if err != nil {
		return nil, apierrors.NewInternalServerError("captcha verification process failed").WithInternalError(err)
	}

	if !verificationResult.Success {
		return nil, apierrors.NewBadRequestError(apierrors.ErrorCodeCaptchaFailed, "captcha protection: request disallowed (%s)", strings.Join(verificationResult.ErrorCodes, ", "))
	}

	return ctx, nil
}

func isIgnoreCaptchaRoute(req *http.Request) bool {
	if req.URL.Path != "/token" {
		return false
	}

	switch req.FormValue("grant_type") {
	case "pkce":
		return true

	case "refresh_token":
		return true

	case "id_token":
		return true

	case "password":
		return false

	case "web3":
		return false
	}

	return false
}

func (a *API) isValidExternalHost(w http.ResponseWriter, req *http.Request) (context.Context, error) {
	ctx := req.Context()
	config := a.config

	xForwardedHost := req.Header.Get("X-Forwarded-Host")
	xForwardedProto := req.Header.Get("X-Forwarded-Proto")
	reqHost := req.URL.Hostname()

	if len(config.Mailer.ExternalHosts) > 0 {
		// this server is configured to accept multiple external hosts, validate the host from the X-Forwarded-Host or Host headers

		hostname := ""
		protocol := "https"

		if xForwardedHost != "" {
			for _, host := range config.Mailer.ExternalHosts {
				if host == xForwardedHost {
					hostname = host
					break
				}
			}
		} else if reqHost != "" {
			for _, host := range config.Mailer.ExternalHosts {
				if host == reqHost {
					hostname = host
					break
				}
			}
		}

		if hostname != "" {
			if hostname == "localhost" {
				// allow the use of HTTP only if the accepted hostname was localhost
				if xForwardedProto == "http" || req.URL.Scheme == "http" {
					protocol = "http"
				}
			}

			externalHostURL, err := url.ParseRequestURI(fmt.Sprintf("%s://%s", protocol, hostname))
			if err != nil {
				return ctx, err
			}

			return withExternalHost(ctx, externalHostURL), nil
		}
	}

	if xForwardedHost != "" || reqHost != "" {
		// host has been provided to the request, but it hasn't been
		// added to the allow list, raise a log message
		// in Supabase platform the X-Forwarded-Host and full request
		// URL are likely sanitzied before they reach the server

		fields := make(logrus.Fields)

		if xForwardedHost != "" {
			fields["x_forwarded_host"] = xForwardedHost
		}

		if xForwardedProto != "" {
			fields["x_forwarded_proto"] = xForwardedProto
		}

		if reqHost != "" {
			fields["request_url_host"] = reqHost

			if req.URL.Scheme != "" {
				fields["request_url_scheme"] = req.URL.Scheme
			}
		}

		logrus.WithFields(fields).Info("Request received external host in X-Forwarded-Host or Host headers, but the values have not been added to GOTRUE_MAILER_EXTERNAL_HOSTS and will not be used. To suppress this message add the host, or sanitize the headers before the request reaches Auth.")
	}

	// either the provided external hosts don't match the allow list, or
	// the server is not configured to accept multiple hosts -- use the
	// configured external URL instead

	externalHostURL, err := url.ParseRequestURI(config.API.ExternalURL)
	if err != nil {
		return ctx, err
	}

	return withExternalHost(ctx, externalHostURL), nil
}

func (a *API) requireSAMLEnabled(w http.ResponseWriter, req *http.Request) (context.Context, error) {
	ctx := req.Context()
	if !a.config.SAML.Enabled {
		return nil, apierrors.NewNotFoundError(apierrors.ErrorCodeSAMLProviderDisabled, "SAML 2.0 is disabled")
	}
	return ctx, nil
}

func (a *API) requireManualLinkingEnabled(w http.ResponseWriter, req *http.Request) (context.Context, error) {
	ctx := req.Context()
	if !a.config.Security.ManualLinkingEnabled {
		return nil, apierrors.NewNotFoundError(apierrors.ErrorCodeManualLinkingDisabled, "Manual linking is disabled")
	}
	return ctx, nil
}

func (a *API) databaseCleanup(cleanup models.Cleaner) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			wrappedResp := chimiddleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(wrappedResp, r)
			switch r.Method {
			case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
				if (wrappedResp.Status() / 100) != 2 {
					// don't do any cleanups for non-2xx responses
					return
				}
				// continue
			default:
				return
			}

			db := a.db.WithContext(r.Context())
			log := observability.GetLogEntry(r).Entry

			affectedRows, err := cleanup.Clean(db)
			if err != nil {
				log.WithError(err).WithField("affected_rows", affectedRows).Warn("database cleanup failed")
			} else if affectedRows > 0 {
				log.WithField("affected_rows", affectedRows).Debug("cleaned up expired or stale rows")
			}
		})
	}
}

// timeoutResponseWriter is a http.ResponseWriter that queues up a response
// body to be sent if the serving completes before the context has exceeded its
// deadline.
type timeoutResponseWriter struct {
	sync.Mutex

	header      http.Header
	wroteHeader bool
	snapHeader  http.Header // snapshot of the header at the time WriteHeader was called
	statusCode  int
	buf         bytes.Buffer
}

func (t *timeoutResponseWriter) Header() http.Header {
	t.Lock()
	defer t.Unlock()

	return t.header
}

func (t *timeoutResponseWriter) Write(bytes []byte) (int, error) {
	t.Lock()
	defer t.Unlock()

	if !t.wroteHeader {
		t.writeHeaderLocked(http.StatusOK)
	}

	return t.buf.Write(bytes)
}

func (t *timeoutResponseWriter) WriteHeader(statusCode int) {
	t.Lock()
	defer t.Unlock()

	t.writeHeaderLocked(statusCode)
}

func (t *timeoutResponseWriter) writeHeaderLocked(statusCode int) {
	if t.wroteHeader {
		// ignore multiple calls to WriteHeader
		// once WriteHeader has been called once, a snapshot of the header map is taken
		// and saved in snapHeader to be used in finallyWrite
		return
	}

	t.statusCode = statusCode
	t.wroteHeader = true
	t.snapHeader = t.header.Clone()
}

func (t *timeoutResponseWriter) finallyWrite(w http.ResponseWriter) {
	t.Lock()
	defer t.Unlock()

	dst := w.Header()
	for k, vv := range t.snapHeader {
		dst[k] = vv
	}

	if !t.wroteHeader {
		t.statusCode = http.StatusOK
	}

	w.WriteHeader(t.statusCode)
	if _, err := w.Write(t.buf.Bytes()); err != nil {
		logrus.WithError(err).Warn("Write failed")
	}
}

func timeoutMiddleware(timeout time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer cancel()

			timeoutWriter := &timeoutResponseWriter{
				header: make(http.Header),
			}

			panicChan := make(chan any, 1)
			serverDone := make(chan struct{})
			go func() {
				defer func() {
					if p := recover(); p != nil {
						panicChan <- p
					}
				}()

				next.ServeHTTP(timeoutWriter, r.WithContext(ctx))
				close(serverDone)
			}()

			select {
			case p := <-panicChan:
				panic(p)

			case <-serverDone:
				timeoutWriter.finallyWrite(w)

			case <-ctx.Done():
				err := ctx.Err()

				if err == context.DeadlineExceeded {
					httpError := &HTTPError{
						HTTPStatus: http.StatusGatewayTimeout,
						ErrorCode:  apierrors.ErrorCodeRequestTimeout,
						Message:    "Processing this request timed out, please retry after a moment.",
					}

					httpError = httpError.WithInternalError(err)

					HandleResponseError(httpError, w, r)
				} else {
					// unrecognized context error, so we should wait for the server to finish
					// and write out the response
					<-serverDone

					timeoutWriter.finallyWrite(w)
				}
			}
		})
	}
}
