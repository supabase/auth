package api

import (
	"sync"
	"time"

	"github.com/supabase/auth/internal/conf"
)

// RateLimiter will limit the number of calls to Allow per interval.
type RateLimiter struct {
	mu    sync.Mutex
	ival  time.Duration // Count is reset and time updated every ival.
	limit int           // Limit calls to Allow() per ival.

	// Guarded by mu.
	last  time.Time // When the limiter was last reset.
	count int       // Total calls to Allow() since time.
}

// newRateLimiter returns a rate limiter configured using the given conf.Rate.
func newRateLimiter(r conf.Rate) *RateLimiter {
	return &RateLimiter{
		ival:  r.OverTime,
		limit: int(r.Events),
		last:  time.Now(),
	}
}

func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	return rl.allowAt(now)
}

func (rl *RateLimiter) allowAt(at time.Time) bool {
	since := at.Sub(rl.last)
	if ivals := int64(since / rl.ival); ivals > 0 {
		rl.last = rl.last.Add(time.Duration(ivals) * rl.ival)
		rl.count = 0
	}
	if rl.count < rl.limit {
		rl.count++
		return true
	}
	return false
}
