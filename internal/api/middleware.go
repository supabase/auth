package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/supabase/gotrue/internal/models"
	"github.com/supabase/gotrue/internal/observability"
	"github.com/supabase/gotrue/internal/security"

	"github.com/didip/tollbooth/v5"
	"github.com/didip/tollbooth/v5/limiter"
	jwt "github.com/golang-jwt/jwt"
)

type FunctionHooks map[string][]string

type NetlifyMicroserviceClaims struct {
	jwt.StandardClaims
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

func (a *API) limitHandler(lmt *limiter.Limiter) middlewareHandler {
	return func(w http.ResponseWriter, req *http.Request) (context.Context, error) {
		c := req.Context()

		if limitHeader := a.config.RateLimitHeader; limitHeader != "" {
			key := req.Header.Get(limitHeader)

			if key == "" {
				log := observability.GetLogEntry(req)
				log.WithField("header", limitHeader).Warn("request does not have a value for the rate limiting header, rate limiting is not applied")
				return c, nil
			} else {
				err := tollbooth.LimitByKeys(lmt, []string{key})
				if err != nil {
					return c, httpError(http.StatusTooManyRequests, "Rate limit exceeded")
				}
			}
		}
		return c, nil
	}
}

func (a *API) limitEmailOrPhoneSentHandler() middlewareHandler {
	// limit per hour
	emailFreq := a.config.RateLimitEmailSent / (60 * 60)
	smsFreq := a.config.RateLimitSmsSent / (60 * 60)

	emailLimiter := tollbooth.NewLimiter(emailFreq, &limiter.ExpirableOptions{
		DefaultExpirationTTL: time.Hour,
	}).SetBurst(int(a.config.RateLimitEmailSent)).SetMethods([]string{"PUT", "POST"})

	phoneLimiter := tollbooth.NewLimiter(smsFreq, &limiter.ExpirableOptions{
		DefaultExpirationTTL: time.Hour,
	}).SetBurst(int(a.config.RateLimitSmsSent)).SetMethods([]string{"PUT", "POST"})

	return func(w http.ResponseWriter, req *http.Request) (context.Context, error) {
		c := req.Context()
		config := a.config
		if (config.External.Email.Enabled && !config.Mailer.Autoconfirm) || (config.External.Phone.Enabled) {
			if req.Method == "PUT" || req.Method == "POST" {
				bodyBytes, err := getBodyBytes(req)
				if err != nil {
					return c, internalServerError("Error invalid request body").WithInternalError(err)
				}

				var requestBody struct {
					Email string `json:"email"`
					Phone string `json:"phone"`
				}

				if err := json.Unmarshal(bodyBytes, &requestBody); err != nil {
					return c, badRequestError("Error invalid request body").WithInternalError(err)
				}

				if requestBody.Email != "" {
					if err := tollbooth.LimitByKeys(emailLimiter, []string{"email_functions"}); err != nil {
						return c, httpError(http.StatusTooManyRequests, "Email rate limit exceeded")
					}
				}

				if requestBody.Phone != "" {
					if err := tollbooth.LimitByKeys(phoneLimiter, []string{"phone_functions"}); err != nil {
						return c, httpError(http.StatusTooManyRequests, "Sms rate limit exceeded")
					}
				}
			}
		}
		return c, nil
	}
}

func (a *API) requireAdminCredentials(w http.ResponseWriter, req *http.Request) (context.Context, error) {
	t, err := a.extractBearerToken(req)
	if err != nil || t == "" {
		return nil, err
	}

	ctx, err := a.parseJWTClaims(t, req)
	if err != nil {
		a.clearCookieTokens(a.config, w)
		return nil, err
	}

	return a.requireAdmin(ctx, w, req)
}

func (a *API) requireEmailProvider(w http.ResponseWriter, req *http.Request) (context.Context, error) {
	ctx := req.Context()
	config := a.config

	if !config.External.Email.Enabled {
		return nil, badRequestError("Email logins are disabled")
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

	verificationResult, err := security.VerifyRequest(req, strings.TrimSpace(config.Security.Captcha.Secret), config.Security.Captcha.Provider)
	if err != nil {
		return nil, internalServerError("captcha verification process failed").WithInternalError(err)
	}

	if !verificationResult.Success {
		return nil, badRequestError("captcha protection: request disallowed (%s)", strings.Join(verificationResult.ErrorCodes, ", "))

	}

	return ctx, nil
}

func isIgnoreCaptchaRoute(req *http.Request) bool {
	// captcha shouldn't be enabled on requests to refresh the token
	if req.URL.Path == "/token" && req.FormValue("grant_type") == "refresh_token" {
		return true
	}
	return false
}

func (a *API) isValidExternalHost(w http.ResponseWriter, req *http.Request) (context.Context, error) {
	ctx := req.Context()
	config := a.config

	var u *url.URL
	var err error

	baseUrl := config.API.ExternalURL
	xForwardedHost := req.Header.Get("X-Forwarded-Host")
	xForwardedProto := req.Header.Get("X-Forwarded-Proto")
	if xForwardedHost != "" && xForwardedProto != "" {
		baseUrl = fmt.Sprintf("%s://%s", xForwardedProto, xForwardedHost)
	} else if req.URL.Scheme != "" && req.URL.Hostname() != "" {
		baseUrl = fmt.Sprintf("%s://%s", req.URL.Scheme, req.URL.Hostname())
	}
	if u, err = url.ParseRequestURI(baseUrl); err != nil {
		// fallback to the default hostname
		log := observability.GetLogEntry(req)
		log.WithField("request_url", baseUrl).Warn(err)
		if u, err = url.ParseRequestURI(config.API.ExternalURL); err != nil {
			return ctx, err
		}
	}
	return withExternalHost(ctx, u), nil
}

func (a *API) requireSAMLEnabled(w http.ResponseWriter, req *http.Request) (context.Context, error) {
	ctx := req.Context()
	if !a.config.SAML.Enabled {
		return nil, notFoundError("SAML 2.0 is disabled")
	}
	return ctx, nil
}

func (a *API) databaseCleanup(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)

		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
			// continue

		default:
			return
		}

		db := a.db.WithContext(r.Context())
		log := observability.GetLogEntry(r)

		affectedRows, err := models.Cleanup(db)
		if err != nil {
			log.WithError(err).WithField("affected_rows", affectedRows).Warn("database cleanup failed")
		} else if affectedRows > 0 {
			log.WithField("affected_rows", affectedRows).Debug("cleaned up expired or stale rows")
		}
	})
}
