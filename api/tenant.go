package api

import (
	"time"

	"github.com/didip/tollbooth/v5"
	"github.com/didip/tollbooth/v5/limiter"
	"github.com/netlify/gotrue/conf"
	"github.com/netlify/gotrue/storage"
	"github.com/sirupsen/logrus"
)

// stores per-tenant settings here
// TODO: need to add tenant-specific rate limiting here
type Tenant struct {
	db       *storage.Connection
	config   *conf.GlobalConfiguration
	limiters map[string]*limiter.Limiter
}

func (t *Tenant) GetConnection() *storage.Connection {
	return t.db
}

func NewTenant(config *conf.GlobalConfiguration) (*Tenant, error) {
	// TODO: close db connection in cleanup
	db, err := storage.Dial(config)
	if err != nil {
		logrus.Fatalf("error opening database connection to tenant: %+v", err)
	}

	// create rate limiters for tenant
	// TODO: in multi-tenant mode, the rate limiters have to be obtained from a global store
	limiters := map[string]*limiter.Limiter{
		// limit per hour
		"email": tollbooth.NewLimiter(config.RateLimitEmailSent/(60*60), &limiter.ExpirableOptions{
			DefaultExpirationTTL: time.Hour,
		}).SetBurst(int(config.RateLimitEmailSent)).SetMethods([]string{"PUT", "POST"}),
		// limit per hour
		"sms": tollbooth.NewLimiter(config.RateLimitSmsSent/(60*60), &limiter.ExpirableOptions{
			DefaultExpirationTTL: time.Hour,
		}).SetBurst(int(config.RateLimitSmsSent)).SetMethods([]string{"PUT", "POST"}),
		// limit per 5 minutes
		"token": tollbooth.NewLimiter(config.RateLimitTokenRefresh/(60*5), &limiter.ExpirableOptions{
			DefaultExpirationTTL: time.Hour,
		}).SetBurst(30),
		// limit per 5 minutes
		"verify": tollbooth.NewLimiter(config.RateLimitVerify/(60*5), &limiter.ExpirableOptions{
			DefaultExpirationTTL: time.Hour,
		}).SetBurst(30),
		// limit per minute
		"mfa/verify": tollbooth.NewLimiter(config.MFA.RateLimitChallengeAndVerify/60, &limiter.ExpirableOptions{
			DefaultExpirationTTL: time.Minute,
		}).SetBurst(30),
		// limit per minute
		"mfa/challenge": tollbooth.NewLimiter(config.MFA.RateLimitChallengeAndVerify/60, &limiter.ExpirableOptions{
			DefaultExpirationTTL: time.Minute,
		}).SetBurst(30),
		// limit per 5 minutes
		"sso": tollbooth.NewLimiter(config.RateLimitSso/(60*5), &limiter.ExpirableOptions{
			DefaultExpirationTTL: time.Hour,
		}).SetBurst(30),
		// limit per 5 minutes
		"sso/assertion": tollbooth.NewLimiter(config.SAML.RateLimitAssertion/(60*5), &limiter.ExpirableOptions{
			DefaultExpirationTTL: time.Hour,
		}).SetBurst(30),
	}

	return &Tenant{
		config:   config,
		db:       db,
		limiters: limiters,
	}, nil
}
