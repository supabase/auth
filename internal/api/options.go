package api

import (
	"time"

	"github.com/didip/tollbooth/v5"
	"github.com/didip/tollbooth/v5/limiter"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/ratelimit"
)

type Option interface {
	apply(*API)
}

type LimiterOptions struct {
	Email ratelimit.Limiter
	Phone ratelimit.Limiter

	Signups          *limiter.Limiter
	AnonymousSignIns *limiter.Limiter
	Recover          *limiter.Limiter
	Resend           *limiter.Limiter
	MagicLink        *limiter.Limiter
	Otp              *limiter.Limiter
	Token            *limiter.Limiter
	Verify           *limiter.Limiter
	User             *limiter.Limiter
	FactorVerify     *limiter.Limiter
	FactorChallenge  *limiter.Limiter
	SSO              *limiter.Limiter
	SAMLAssertion    *limiter.Limiter
	Web3             *limiter.Limiter
}

func (lo *LimiterOptions) apply(a *API) { a.limiterOpts = lo }

func NewLimiterOptions(gc *conf.GlobalConfiguration) *LimiterOptions {
	o := &LimiterOptions{}

	o.Email = ratelimit.New(gc.RateLimitEmailSent)
	o.Phone = ratelimit.New(gc.RateLimitSmsSent)

	o.AnonymousSignIns = tollbooth.NewLimiter(gc.RateLimitAnonymousUsers/(60*60),
		&limiter.ExpirableOptions{
			DefaultExpirationTTL: time.Hour,
		}).SetBurst(int(gc.RateLimitAnonymousUsers)).SetMethods([]string{"POST"})

	o.Token = tollbooth.NewLimiter(gc.RateLimitTokenRefresh/(60*5),
		&limiter.ExpirableOptions{
			DefaultExpirationTTL: time.Hour,
		}).SetBurst(30)

	o.Verify = tollbooth.NewLimiter(gc.RateLimitVerify/(60*5),
		&limiter.ExpirableOptions{
			DefaultExpirationTTL: time.Hour,
		}).SetBurst(30)

	o.User = tollbooth.NewLimiter(gc.RateLimitOtp/(60*5),
		&limiter.ExpirableOptions{
			DefaultExpirationTTL: time.Hour,
		}).SetBurst(30)

	o.FactorVerify = tollbooth.NewLimiter(gc.MFA.RateLimitChallengeAndVerify/60,
		&limiter.ExpirableOptions{
			DefaultExpirationTTL: time.Minute,
		}).SetBurst(30)

	o.FactorChallenge = tollbooth.NewLimiter(gc.MFA.RateLimitChallengeAndVerify/60,
		&limiter.ExpirableOptions{
			DefaultExpirationTTL: time.Minute,
		}).SetBurst(30)

	o.SSO = tollbooth.NewLimiter(gc.RateLimitSso/(60*5),
		&limiter.ExpirableOptions{
			DefaultExpirationTTL: time.Hour,
		}).SetBurst(30)

	o.SAMLAssertion = tollbooth.NewLimiter(gc.SAML.RateLimitAssertion/(60*5),
		&limiter.ExpirableOptions{
			DefaultExpirationTTL: time.Hour,
		}).SetBurst(30)

	o.Signups = tollbooth.NewLimiter(gc.RateLimitOtp/(60*5),
		&limiter.ExpirableOptions{
			DefaultExpirationTTL: time.Hour,
		}).SetBurst(30)

	o.Web3 = tollbooth.NewLimiter(gc.RateLimitWeb3/(60*5),
		&limiter.ExpirableOptions{
			DefaultExpirationTTL: time.Hour,
		}).SetBurst(30)

	// These all use the OTP limit per 5 min with 1hour ttl and burst of 30.
	o.Recover = newLimiterPer5mOver1h(gc.RateLimitOtp)
	o.Resend = newLimiterPer5mOver1h(gc.RateLimitOtp)
	o.MagicLink = newLimiterPer5mOver1h(gc.RateLimitOtp)
	o.Otp = newLimiterPer5mOver1h(gc.RateLimitOtp)
	return o
}

func newLimiterPer5mOver1h(rate float64) *limiter.Limiter {
	freq := rate / (60 * 5)
	lim := tollbooth.NewLimiter(freq, &limiter.ExpirableOptions{
		DefaultExpirationTTL: time.Hour,
	}).SetBurst(30)
	return lim
}
