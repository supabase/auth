package api

import (
	"time"

	"github.com/didip/tollbooth/v5"
	"github.com/didip/tollbooth/v5/limiter"
	"github.com/supabase/gotrue/internal/conf"
)

type rateLimiterType int

const (
	RateLimitEmailSent rateLimiterType = iota
	RateLimitSmsSent
	RateLimitTokenRefresh
	RateLimitVerify
	RateLimitMFAVerify
	RateLimitMFAChallenge
	RateLimitSSO
	RateLimitSSOAssertion
)

type Limiters struct {
	EmailSent    *limiter.Limiter
	SmsSent      *limiter.Limiter
	TokenRefresh *limiter.Limiter
	Verify       *limiter.Limiter
	MFAVerify    *limiter.Limiter
	MFAChallenge *limiter.Limiter
	SSO          *limiter.Limiter
	SSOAssertion *limiter.Limiter
}

func NewLimiters(config *conf.GlobalConfiguration) *Limiters {
	return &Limiters{
		EmailSent: tollbooth.NewLimiter(config.RateLimitEmailSent/(60*60), &limiter.ExpirableOptions{
			DefaultExpirationTTL: time.Hour,
		}).SetBurst(int(config.RateLimitEmailSent)).SetMethods([]string{"PUT", "POST"}),
		SmsSent: tollbooth.NewLimiter(config.RateLimitSmsSent/(60*60), &limiter.ExpirableOptions{
			DefaultExpirationTTL: time.Hour,
		}).SetBurst(int(config.RateLimitSmsSent)).SetMethods([]string{"PUT", "POST"}),
		// limit per 5 minutes
		TokenRefresh: tollbooth.NewLimiter(config.RateLimitTokenRefresh/(60*5), &limiter.ExpirableOptions{
			DefaultExpirationTTL: time.Hour,
		}).SetBurst(30),
		// limit per 5 minutes
		Verify: tollbooth.NewLimiter(config.RateLimitVerify/(60*5), &limiter.ExpirableOptions{
			DefaultExpirationTTL: time.Hour,
		}).SetBurst(30),
		// limit per minute
		MFAVerify: tollbooth.NewLimiter(config.MFA.RateLimitChallengeAndVerify/60, &limiter.ExpirableOptions{
			DefaultExpirationTTL: time.Minute,
		}).SetBurst(30),
		// limit per minute
		MFAChallenge: tollbooth.NewLimiter(config.MFA.RateLimitChallengeAndVerify/60, &limiter.ExpirableOptions{
			DefaultExpirationTTL: time.Minute,
		}).SetBurst(30),
		// limit per 5 minutes
		SSO: tollbooth.NewLimiter(config.RateLimitSso/(60*5), &limiter.ExpirableOptions{
			DefaultExpirationTTL: time.Hour,
		}).SetBurst(30),
		// limit per 5 minutes
		SSOAssertion: tollbooth.NewLimiter(config.SAML.RateLimitAssertion/(60*5), &limiter.ExpirableOptions{
			DefaultExpirationTTL: time.Hour,
		}).SetBurst(30),
	}
}
