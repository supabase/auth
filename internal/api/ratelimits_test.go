package api

import (
	"fmt"
	"testing"
	"time"

	"github.com/supabase/auth/internal/conf"
	"golang.org/x/time/rate"
)

func newUnlimitedLimiter() *rate.Limiter {
	return rate.NewLimiter(rate.Inf, 0)
}

func Example_newRateLimiter() {
	now, _ := time.Parse(time.RFC3339, "2024-09-24T10:00:00.00Z")
	{
		cfg := conf.Rate{Events: 100, OverTime: time.Hour * 24}
		rl := newRateLimiter(cfg)
		cur := now
		for i := 0; i < 61; i++ {
			fmt.Printf("%-5v @ %v\n", rl.AllowN(cur, 1), cur)
			cur = cur.Add(time.Minute)
		}
	}

	// Output:
	// true  @ 2024-09-24 10:00:00 +0000 UTC
	// false @ 2024-09-24 10:01:00 +0000 UTC
	// false @ 2024-09-24 10:02:00 +0000 UTC
	// false @ 2024-09-24 10:03:00 +0000 UTC
	// false @ 2024-09-24 10:04:00 +0000 UTC
	// false @ 2024-09-24 10:05:00 +0000 UTC
	// false @ 2024-09-24 10:06:00 +0000 UTC
	// false @ 2024-09-24 10:07:00 +0000 UTC
	// false @ 2024-09-24 10:08:00 +0000 UTC
	// false @ 2024-09-24 10:09:00 +0000 UTC
	// false @ 2024-09-24 10:10:00 +0000 UTC
	// false @ 2024-09-24 10:11:00 +0000 UTC
	// false @ 2024-09-24 10:12:00 +0000 UTC
	// false @ 2024-09-24 10:13:00 +0000 UTC
	// false @ 2024-09-24 10:14:00 +0000 UTC
	// true  @ 2024-09-24 10:15:00 +0000 UTC
	// false @ 2024-09-24 10:16:00 +0000 UTC
	// false @ 2024-09-24 10:17:00 +0000 UTC
	// false @ 2024-09-24 10:18:00 +0000 UTC
	// false @ 2024-09-24 10:19:00 +0000 UTC
	// false @ 2024-09-24 10:20:00 +0000 UTC
	// false @ 2024-09-24 10:21:00 +0000 UTC
	// false @ 2024-09-24 10:22:00 +0000 UTC
	// false @ 2024-09-24 10:23:00 +0000 UTC
	// false @ 2024-09-24 10:24:00 +0000 UTC
	// false @ 2024-09-24 10:25:00 +0000 UTC
	// false @ 2024-09-24 10:26:00 +0000 UTC
	// false @ 2024-09-24 10:27:00 +0000 UTC
	// false @ 2024-09-24 10:28:00 +0000 UTC
	// false @ 2024-09-24 10:29:00 +0000 UTC
	// true  @ 2024-09-24 10:30:00 +0000 UTC
	// false @ 2024-09-24 10:31:00 +0000 UTC
	// false @ 2024-09-24 10:32:00 +0000 UTC
	// false @ 2024-09-24 10:33:00 +0000 UTC
	// false @ 2024-09-24 10:34:00 +0000 UTC
	// false @ 2024-09-24 10:35:00 +0000 UTC
	// false @ 2024-09-24 10:36:00 +0000 UTC
	// false @ 2024-09-24 10:37:00 +0000 UTC
	// false @ 2024-09-24 10:38:00 +0000 UTC
	// false @ 2024-09-24 10:39:00 +0000 UTC
	// false @ 2024-09-24 10:40:00 +0000 UTC
	// false @ 2024-09-24 10:41:00 +0000 UTC
	// false @ 2024-09-24 10:42:00 +0000 UTC
	// false @ 2024-09-24 10:43:00 +0000 UTC
	// false @ 2024-09-24 10:44:00 +0000 UTC
	// true  @ 2024-09-24 10:45:00 +0000 UTC
	// false @ 2024-09-24 10:46:00 +0000 UTC
	// false @ 2024-09-24 10:47:00 +0000 UTC
	// false @ 2024-09-24 10:48:00 +0000 UTC
	// false @ 2024-09-24 10:49:00 +0000 UTC
	// false @ 2024-09-24 10:50:00 +0000 UTC
	// false @ 2024-09-24 10:51:00 +0000 UTC
	// false @ 2024-09-24 10:52:00 +0000 UTC
	// false @ 2024-09-24 10:53:00 +0000 UTC
	// false @ 2024-09-24 10:54:00 +0000 UTC
	// false @ 2024-09-24 10:55:00 +0000 UTC
	// false @ 2024-09-24 10:56:00 +0000 UTC
	// false @ 2024-09-24 10:57:00 +0000 UTC
	// false @ 2024-09-24 10:58:00 +0000 UTC
	// false @ 2024-09-24 10:59:00 +0000 UTC
	// true  @ 2024-09-24 11:00:00 +0000 UTC

}

func TestNewRateLimiter(t *testing.T) {
	now, _ := time.Parse(time.RFC3339, "2024-09-24T10:00:00.00Z")

	type event struct {
		ok bool
		at time.Time
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
				{true, now},
				{false, now.Add(time.Minute)},
				{false, now.Add(time.Minute)},
				{false, now.Add(time.Minute * 14)},
				{true, now.Add(time.Minute * 15)},
				{false, now.Add(time.Minute * 16)},
				{false, now.Add(time.Minute * 17)},
				{true, now.Add(time.Minute * 30)},
			},
		},
	}
	for _, tc := range cases {
		rl := newRateLimiter(tc.cfg)
		for _, evt := range tc.evts {
			if exp, got := evt.ok, rl.AllowN(evt.at, 1); exp != got {
				t.Fatalf("exp AllowN(%v, 1) to be %v; got %v", evt.at, exp, got)
			}
		}
	}
}
