package ratelimit

import (
	"time"

	"github.com/supabase/auth/internal/conf"
)

// Limiter is the interface implemented by rate limiters.
//
// Implementations of Limiter must be safe for concurrent use.
type Limiter interface {

	// Allow should return true if an event should be allowed at the time
	// which it was called, or false otherwise.
	Allow() bool

	// AllowAt should return true if an event should be allowed at the given
	// time, or false otherwise.
	AllowAt(at time.Time) bool
}

// New returns a new Limiter based on the given config.
//
// When the type is conf.BurstRateType it returns a BurstLimiter, otherwise
// New returns an IntervalLimiter.
func New(r conf.Rate) Limiter {
	switch r.GetRateType() {
	case conf.BurstRateType:
		return NewBurstLimiter(r)
	default:
		return NewIntervalLimiter(r)
	}
}
