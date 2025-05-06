package ratelimit

import (
	"testing"

	"github.com/supabase/auth/internal/conf"
)

func TestNew(t *testing.T) {

	// IntervalLimiter
	{
		var r conf.Rate
		err := r.Decode("100")
		if err != nil {
			t.Fatalf("exp nil err; got %v", err)
		}

		rl := New(r)
		if _, ok := rl.(*IntervalLimiter); !ok {
			t.Fatalf("exp type *IntervalLimiter; got %T", rl)
		}
	}
	{
		var r conf.Rate
		err := r.Decode("100.123")
		if err != nil {
			t.Fatalf("exp nil err; got %v", err)
		}

		rl := New(r)
		if _, ok := rl.(*IntervalLimiter); !ok {
			t.Fatalf("exp type *IntervalLimiter; got %T", rl)
		}
	}

	// BurstLimiter
	{
		var r conf.Rate
		err := r.Decode("20/200s")
		if err != nil {
			t.Fatalf("exp nil err; got %v", err)
		}

		rl := New(r)
		if _, ok := rl.(*BurstLimiter); !ok {
			t.Fatalf("exp type *BurstLimiter; got %T", rl)
		}
	}
}
