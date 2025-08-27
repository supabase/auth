package api

import (
	"time"

	"github.com/didip/tollbooth/v5"
	"github.com/didip/tollbooth/v5/limiter"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/mailer"
	"github.com/supabase/auth/internal/ratelimit"
	"github.com/supabase/auth/internal/tokens"
)

type Option interface {
	apply(*API)
}

type MailerOptions struct {
	MailerClientFunc func() mailer.MailClient
}

func (mo *MailerOptions) apply(a *API) { a.mailerClientFunc = mo.MailerClientFunc }

type LimiterOptions struct {
	Email ratelimit.Limiter
	Phone ratelimit.Limiter

	Signups             *limiter.Limiter
	AnonymousSignIns    *limiter.Limiter
	Recover             *limiter.Limiter
	Resend              *limiter.Limiter
	MagicLink           *limiter.Limiter
	Otp                 *limiter.Limiter
	Token               *limiter.Limiter
	Verify              *limiter.Limiter
	User                *limiter.Limiter
	FactorVerify        *limiter.Limiter
	FactorChallenge     *limiter.Limiter
	SSO                 *limiter.Limiter
	SAMLAssertion       *limiter.Limiter
	Web3                *limiter.Limiter
	OAuthClientRegister *limiter.Limiter
}

func (lo *LimiterOptions) apply(a *API) { a.limiterOpts = lo }

// TokenServiceOption allows injecting a custom token service
type TokenServiceOption struct {
	service *tokens.Service
}

func WithTokenService(service *tokens.Service) *TokenServiceOption {
	return &TokenServiceOption{service: service}
}

func (tso *TokenServiceOption) apply(a *API) {
	a.tokenService = tso.service
}

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

	o.Web3 = tollbooth.NewLimiter(gc.RateLimitWeb3/(60*5),
		&limiter.ExpirableOptions{
			DefaultExpirationTTL: time.Hour,
		}).SetBurst(30)

	// These all use the OTP limit per 5 min with 1hour ttl and burst of 30.
	o.Recover = newLimiterPer5mOver1h(gc.RateLimitOtp)
	o.Resend = newLimiterPer5mOver1h(gc.RateLimitOtp)
	o.MagicLink = newLimiterPer5mOver1h(gc.RateLimitOtp)
	o.Otp = newLimiterPer5mOver1h(gc.RateLimitOtp)
	o.User = newLimiterPer5mOver1h(gc.RateLimitOtp)
	o.Signups = newLimiterPer5mOver1h(gc.RateLimitOtp)
	o.OAuthClientRegister = newLimiterPer5mOver1h(gc.RateLimitOAuthDynamicClientRegister)

	return o
}

func newLimiterPer5mOver1h(rate float64) *limiter.Limiter {
	freq := rate / (60 * 5)
	lim := tollbooth.NewLimiter(freq, &limiter.ExpirableOptions{
		DefaultExpirationTTL: time.Hour,
	}).SetBurst(30)
	return lim
}
