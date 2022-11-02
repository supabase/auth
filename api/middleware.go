package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/netlify/gotrue/observability"
	"github.com/netlify/gotrue/security"

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
	freq := a.config.RateLimitEmailSent / (60 * 60)
	lmt := tollbooth.NewLimiter(freq, &limiter.ExpirableOptions{
		DefaultExpirationTTL: time.Hour,
	}).SetBurst(int(a.config.RateLimitEmailSent)).SetMethods([]string{"PUT", "POST"})
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
					if err := tollbooth.LimitByKeys(lmt, []string{"email_functions"}); err != nil {
						return c, httpError(http.StatusTooManyRequests, "Rate limit exceeded")
					}
				}

				if requestBody.Phone != "" {
					if err := tollbooth.LimitByKeys(lmt, []string{"phone_functions"}); err != nil {
						return c, httpError(http.StatusTooManyRequests, "Rate limit exceeded")
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

	ctx, err := a.parseJWTClaims(t, req, w)
	if err != nil {
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

	verificationResult, err := security.VerifyRequest(req, strings.TrimSpace(config.Security.Captcha.Secret))
	if err != nil {
		return nil, internalServerError("hCaptcha verification process failed").WithInternalError(err)
	}

	if !verificationResult.Success {
		return nil, badRequestError("hCaptcha protection: request disallowed (%s)", strings.Join(verificationResult.ErrorCodes, ", "))

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
