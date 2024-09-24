package api

import (
	"github.com/supabase/auth/internal/conf"
	"golang.org/x/time/rate"
)

// newRateLimiter returns a rate limiter configured using the given conf.Rate.
//
// The returned *rate.Limiter will be configured with a token bucket containing
// a single token, which will fill up at a rate of r. For example to allow 100
// events every 24 hours. This will fill a token bucket approximately once every
// 864 seconds (14.4 minutes). See Example_newRateLimiter for a visualization.
func newRateLimiter(r conf.Rate) *rate.Limiter {
	// The rate limiter deals in events per second.
	eps := r.EventsPerSecond()
	const burst = 1

	// NewLimiter will have an initial token bucket of size `burst`. It will
	// be refilled at a rate of `eps` indefinitely. Note that the expression
	// 100 / 24h is roughly equivelant to the expression 1 / 15m. The 100 is
	// a rate, not a quota.
	return rate.NewLimiter(rate.Limit(eps), burst)
}
