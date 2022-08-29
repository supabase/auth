package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/netlify/gotrue/security"
	"github.com/sirupsen/logrus"

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
			key := req.Header.Get(a.config.RateLimitHeader)
			err := tollbooth.LimitByKeys(lmt, []string{key})
			if err != nil {
				return c, httpError(http.StatusTooManyRequests, "Rate limit exceeded")
			}
		}
		return c, nil
	}
}

func (a *API) limitEmailSentHandler() middlewareHandler {
	// limit per hour
	freq := a.config.RateLimitEmailSent / (60 * 60)
	lmt := tollbooth.NewLimiter(freq, &limiter.ExpirableOptions{
		DefaultExpirationTTL: time.Hour,
	}).SetBurst(int(a.config.RateLimitEmailSent)).SetMethods([]string{"PUT", "POST"})
	return func(w http.ResponseWriter, req *http.Request) (context.Context, error) {
		c := req.Context()
		config := a.config
		if config.External.Email.Enabled && !config.Mailer.Autoconfirm {
			if req.Method == "PUT" || req.Method == "POST" {
				res := make(map[string]interface{})
				bodyBytes, err := ioutil.ReadAll(req.Body)
				if err != nil {
					return c, internalServerError("Error invalid request body").WithInternalError(err)
				}
				req.Body.Close()
				req.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

				jsonDecoder := json.NewDecoder(bytes.NewBuffer(bodyBytes))
				if err := jsonDecoder.Decode(&res); err != nil {
					return c, badRequestError("Error invalid request body").WithInternalError(err)
				}

				if _, ok := res["email"]; !ok {
					// email not in POST body
					return c, nil
				}

				if err := tollbooth.LimitByKeys(lmt, []string{"email_functions"}); err != nil {
					return c, httpError(http.StatusTooManyRequests, "Rate limit exceeded")
				}
			}
		}
		return c, nil
	}
}

func (a *API) requireAdminCredentials(w http.ResponseWriter, req *http.Request) (context.Context, error) {
	t, err := a.extractBearerToken(w, req)
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
	if config.Security.Captcha.Provider != "hcaptcha" {
		logrus.WithField("provider", config.Security.Captcha.Provider).Warn("Unsupported captcha provider")
		return nil, internalServerError("server misconfigured")
	}
	secret := strings.TrimSpace(config.Security.Captcha.Secret)
	if secret == "" {
		return nil, internalServerError("server misconfigured")
	}

	verificationResult, err := security.VerifyRequest(req, secret)
	if err != nil {
		logrus.WithField("err", err).Infof("failed to validate result")
		return nil, internalServerError("request validation failure")
	}
	if verificationResult == security.VerificationProcessFailure {
		return nil, internalServerError("request validation failure")
	} else if verificationResult == security.UserRequestFailed {
		return nil, badRequestError("request disallowed")
	}
	if verificationResult != security.SuccessfullyVerified {
		return nil, internalServerError("")
	}
	return ctx, nil
}
