package mailer

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestValidateEmail(t *testing.T) {
	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, time.Second*60)
	defer cancel()

	cases := []struct {
		email   string
		timeout time.Duration
		err     string
	}{
		// valid (has mx record)
		{email: "a@supabase.io"},
		{email: "support@supabase.io"},
		{email: "chris.stockton@supabase.io"},

		// bad format
		{email: "", err: "invalid email format"},
		{email: "io", err: "invalid email format"},
		{email: "supabase.io", err: "invalid email format"},
		{email: "@supabase.io", err: "invalid email format"},

		// invalid: valid mx records, but invalid and often typed
		// (invalidEmailMap)
		{email: "test@test.com", err: "invalid email address"},
		{email: "test@gmail.com", err: "invalid email address"},
		{email: "test@email.com", err: "invalid email address"},

		// invalid: valid mx records, but invalid and often typed
		// (invalidHostMap)
		{email: "a@example.com", err: "invalid email address"},
		{email: "a@example.net", err: "invalid email address"},
		{email: "a@example.org", err: "invalid email address"},

		// invalid: no mx records
		{email: "a@test", err: "invalid email address"},
		{email: "test@local", err: "invalid email address"},
		{email: "test@example", err: "invalid email address"},
		{email: "test@invalid", err: "invalid email address"},

		// valid but not actually valid and typed a lot
		{email: "a@invalid", err: "invalid email address"},
		{email: "test@invalid", err: "invalid email address"},

		// various invalid emails
		{email: "test@test.localhost", err: "invalid email address"},
		{email: "test@invalid.example.com", err: "invalid email address"},
		{email: "test@no.such.email.host.supabase.io", err: "invalid email address"},

		// this low timeout should simulate a dns timeout, which should
		// not be treated as an invalid email.
		{email: "test@test.localhost", timeout: time.Millisecond},

		// likewise for a valid email
		{email: "support@supabase.io", timeout: time.Millisecond},
	}
	for idx, tc := range cases {
		func(timeout time.Duration) {
			if timeout == 0 {
				timeout = validateEmailTimeout
			}

			ctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			now := time.Now()
			err := validateEmail(ctx, tc.email)
			dur := time.Since(now)
			if max := timeout + (time.Millisecond * 50); max < dur {
				t.Fatal("timeout was not respected")
			}

			t.Logf("tc #%v - email %v", idx, tc.email)
			if tc.err != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.err)
				return
			}
			require.NoError(t, err)

		}(tc.timeout)
	}
}
