package api

import (
	"fmt"
	"testing"
	"time"

	"github.com/supabase/auth/internal/conf"
)

func Example_newRateLimiter() {
	now, _ := time.Parse(time.RFC3339, "2024-09-24T10:00:00.00Z")
	cfg := conf.Rate{Events: 100, OverTime: time.Hour * 24}
	rl := newRateLimiter(cfg)
	rl.last = now

	cur := now
	allowed := 0

	for days := 0; days < 2; days++ {
		// First 100 events succeed.
		for i := 0; i < 100; i++ {
			allow := rl.allowAt(cur)
			cur = cur.Add(time.Second)

			if !allow {
				fmt.Printf("false @ %v after %v events... [FAILED]\n", cur, allowed)
				return
			}
			allowed++
		}
		fmt.Printf("true  @ %v for last %v events...\n", cur, allowed)

		// We try hourly until it allows us to make requests again.
		denied := 0
		for i := 0; i < 23; i++ {
			cur = cur.Add(time.Hour)
			allow := rl.allowAt(cur)
			if allow {
				fmt.Printf("true  @ %v before quota reset... [FAILED]\n", cur)
				return
			}
			denied++
		}
		fmt.Printf("false @ %v for last %v events...\n", cur, denied)

		cur = cur.Add(time.Hour)
	}

	// Output:
	// true  @ 2024-09-24 10:01:40 +0000 UTC for last 100 events...
	// false @ 2024-09-25 09:01:40 +0000 UTC for last 23 events...
	// true  @ 2024-09-25 10:03:20 +0000 UTC for last 200 events...
	// false @ 2024-09-26 09:03:20 +0000 UTC for last 23 events...
}

func TestNewRateLimiter(t *testing.T) {
	now, _ := time.Parse(time.RFC3339, "2024-09-24T10:00:00.00Z")

	type event struct {
		ok bool
		at time.Time
		r  int
	}
	cases := []struct {
		cfg  conf.Rate
		now  time.Time
		evts []event
	}{
		{
			cfg: conf.Rate{Events: 100, OverTime: time.Hour * 24},
			now: now,
			evts: []event{
				{true, now, 0},
				{true, now.Add(time.Minute), 98},
				{false, now.Add(time.Minute), 0},
				{false, now.Add(time.Minute * 14), 0},
				{false, now.Add(time.Minute * 15), 0},
				{false, now.Add(time.Minute * 16), 0},
				{false, now.Add(time.Minute * 17), 0},
				{false, now.Add(time.Minute * 17), 0},
				{true, now.Add(time.Hour * 24), 0},
				{true, now.Add(time.Hour * 25), 0},
			},
		},
		{
			cfg: conf.Rate{Events: 0, OverTime: time.Hour},
			now: now,
			evts: []event{
				{false, now.Add(-time.Hour), 0},
				{false, now, 0},
				{false, now.Add(time.Minute), 0},
				{false, now.Add(time.Hour), 0},
				{false, now.Add(time.Hour), 12},
				{false, now.Add(time.Hour * 24), 0},
				{false, now.Add(time.Hour * 24 * 2), 0},
			},
		},
		{
			cfg: conf.Rate{Events: 0, OverTime: time.Hour * 24},
			now: now,
			evts: []event{
				{false, now.Add(-time.Hour), 0},
				{false, now, 0},
				{false, now.Add(time.Minute), 0},
				{false, now.Add(time.Hour), 0},
				{false, now.Add(time.Hour), 12},
				{false, now.Add(time.Hour * 24), 0},
				{false, now.Add(time.Hour * 24 * 2), 0},
			},
		},
	}
	for _, tc := range cases {
		rl := newRateLimiter(tc.cfg)
		rl.last = tc.now

		for _, evt := range tc.evts {
			for i := 0; i <= evt.r; i++ {
				if exp, got := evt.ok, rl.allowAt(evt.at); exp != got {
					t.Fatalf("exp AllowN(%v, 1) to be %v; got %v", evt.at, exp, got)
				}
			}
		}
	}
}
