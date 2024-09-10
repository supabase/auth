package api

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/supabase/auth/internal/conf"
)

// SimpleRateLimiter holds a rate limiter that implements a token-bucket
// algorithm. Rate.OverTime is the duration at which the bucket is filled, and
// Rate.Events is the number of tokens in the bucket.
//
// Internally it uses an atomically increasing counter that resets to 0 on
// every OverTime tick.
//
// You should always use NewSimpleRateLimiter to create a new one.
type SimpleRateLimiter struct {
	Rate conf.Rate

	ticker  *time.Ticker
	counter uint64
}

// NewSimpleRateLimiter creates a new rate limiter starting at the specified
// time and with the specified Rate.
//
// Initially the bucket is filled with a proprotion of the Rate.Events
// depending on how close to the Rate.OverTime tick it has been crated. This is
// one way of making sure that server restarts do not give out a too big of a
// rate limit, as the counter is reset.
func NewSimpleRateLimiter(now time.Time, rate conf.Rate) *SimpleRateLimiter {
	r := &SimpleRateLimiter{
		Rate: rate,
	}

	counterStartedAt := now.Truncate(rate.OverTime)
	counterResetsAt := counterStartedAt.Add(rate.OverTime)

	proRate := float64(counterStartedAt.Sub(now).Milliseconds()) / float64(rate.OverTime.Milliseconds())

	r.counter = uint64(rate.Events * proRate)
	r.ticker = time.NewTicker(counterResetsAt.Sub(now))

	go r.fillBucket()

	return r
}

func (r *SimpleRateLimiter) Increment(events uint64) bool {
	fmt.Printf("@@@@@@@@@@@@@@@@@@@@@@@ %d %f\n", r.counter, r.Rate.Events)
	return atomic.AddUint64(&r.counter, events) < uint64(r.Rate.Events)
}

func (r *SimpleRateLimiter) fillBucket() {
	if _, ok := <-r.ticker.C; !ok {
		return
	}

	// reset ticker to start ticking at the OverTime rate, as it was
	// initially set up to tick at the next aligned OverTime event
	r.ticker.Reset(r.Rate.OverTime)

	// reset counter
	atomic.StoreUint64(&r.counter, 0)

	// then keep resetting at regular OverTime intervals
	for range r.ticker.C {
		atomic.StoreUint64(&r.counter, 0)
	}
}

func (r *SimpleRateLimiter) Close() {
	if r.ticker != nil {
		r.ticker.Stop()
	}
}
