package mailer

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
)

func TestEmalValidatorService(t *testing.T) {
	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, time.Second*60)
	defer cancel()

	testResVal := new(atomic.Value)
	testResVal.Store(`{"valid": true}`)

	testHdrsVal := new(atomic.Value)
	testHdrsVal.Store(map[string]string{"apikey": "test"})

	// testHeaders := map[string][]string{"apikey": []string{"test"}}
	testHeaders := `{"apikey": ["test"]}`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("apikey")
		if key == "" {
			fmt.Fprintln(w, `{"error": true}`)
			return
		}

		fmt.Fprintln(w, testResVal.Load().(string))
	}))
	defer ts.Close()

	// Return nil err from service
	//   when svc and extended checks both report email as valid
	{
		testResVal.Store(`{"valid": true}`)
		cfg := conf.MailerConfiguration{
			EmailValidationExtended:       true,
			EmailValidationServiceURL:     ts.URL,
			EmailValidationServiceHeaders: testHeaders,
		}
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}

		ev := newEmailValidator(cfg)
		err := ev.Validate(ctx, "chris.stockton@supabase.io")
		if err != nil {
			t.Fatalf("exp nil err; got %v", err)
		}
	}

	// Return nil err from service when
	//   extended is disabled for a known invalid address
	//   service reports valid
	{
		testResVal.Store(`{"valid": true}`)

		cfg := conf.MailerConfiguration{
			EmailValidationExtended:       false,
			EmailValidationServiceURL:     ts.URL,
			EmailValidationServiceHeaders: testHeaders,
		}
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}

		ev := newEmailValidator(cfg)
		err := ev.Validate(ctx, "test@gmail.com")
		if err != nil {
			t.Fatalf("exp nil err; got %v", err)
		}
	}

	// Return nil err from service when
	//   extended is disabled for a known invalid address
	//   service is disabled for a known invalid address
	{
		testResVal.Store(`{"valid": false}`)

		cfg := conf.MailerConfiguration{
			EmailValidationExtended:       false,
			EmailValidationServiceURL:     "",
			EmailValidationServiceHeaders: "",
		}
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}

		ev := newEmailValidator(cfg)
		err := ev.Validate(ctx, "test@gmail.com")
		if err != nil {
			t.Fatalf("exp nil err; got %v", err)
		}
	}

	// Return err from service when
	//   extended reports invalid
	//   service is disabled for a known invalid address
	{
		testResVal.Store(`{"valid": true}`)
		cfg := conf.MailerConfiguration{
			EmailValidationExtended:       true,
			EmailValidationServiceURL:     "",
			EmailValidationServiceHeaders: "",
		}
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}

		ev := newEmailValidator(cfg)
		err := ev.Validate(ctx, "test@gmail.com")
		if err == nil {
			t.Fatal("exp non-nil err")
		}
	}

	// Return err from service when
	//   extended reports invalid
	//   service reports valid
	{
		testResVal.Store(`{"valid": true}`)
		cfg := conf.MailerConfiguration{
			EmailValidationExtended:       true,
			EmailValidationServiceURL:     ts.URL,
			EmailValidationServiceHeaders: testHeaders,
		}
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}

		ev := newEmailValidator(cfg)
		err := ev.Validate(ctx, "test@gmail.com")
		if err == nil {
			t.Fatal("exp non-nil err")
		}
	}

	// Return err from service when
	//   extended reports valid
	//   service reports invalid
	{
		testResVal.Store(`{"valid": false}`)
		cfg := conf.MailerConfiguration{
			EmailValidationExtended:       true,
			EmailValidationServiceURL:     ts.URL,
			EmailValidationServiceHeaders: testHeaders,
		}
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}

		ev := newEmailValidator(cfg)
		err := ev.Validate(ctx, "chris.stockton@supabase.io")
		if err == nil {
			t.Fatal("exp non-nil err")
		}
	}

	// Return err from service when
	//   extended reports invalid
	//   service reports invalid
	{
		testResVal.Store(`{"valid": false}`)

		cfg := conf.MailerConfiguration{
			EmailValidationExtended:       false,
			EmailValidationServiceURL:     ts.URL,
			EmailValidationServiceHeaders: testHeaders,
		}
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}

		ev := newEmailValidator(cfg)
		err := ev.Validate(ctx, "test@gmail.com")
		if err == nil {
			t.Fatal("exp non-nil err")
		}
	}
}

func TestValidateEmailExtended(t *testing.T) {
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
		{email: "", err: "invalid_email_format"},
		{email: "io", err: "invalid_email_format"},
		{email: "supabase.io", err: "invalid_email_format"},
		{email: "@supabase.io", err: "invalid_email_format"},
		{email: "test@.supabase.io", err: "invalid_email_format"},

		// invalid: valid mx records, but invalid and often typed
		// (invalidEmailMap)
		{email: "test@email.com", err: "invalid_email_address"},
		{email: "test@gmail.com", err: "invalid_email_address"},
		{email: "test@test.com", err: "invalid_email_dns"},

		// very common typo
		{email: "test@gamil.com", err: "invalid_email_dns"},

		// invalid: valid mx records, but invalid and often typed
		// (invalidHostMap)
		{email: "a@example.com", err: "invalid_email_dns"},
		{email: "a@example.net", err: "invalid_email_dns"},
		{email: "a@example.org", err: "invalid_email_dns"},

		// invalid: no mx records
		{email: "a@test", err: "invalid_email_dns"},
		{email: "test@local", err: "invalid_email_dns"},
		{email: "test@test.local", err: "invalid_email_dns"},
		{email: "test@example", err: "invalid_email_dns"},
		{email: "test@invalid", err: "invalid_email_dns"},

		// valid but not actually valid and typed a lot
		{email: "a@invalid", err: "invalid_email_dns"},
		{email: "a@a.invalid", err: "invalid_email_dns"},
		{email: "test@invalid", err: "invalid_email_dns"},

		// various invalid emails
		{email: "test@test.localhost", err: "invalid_email_dns"},
		{email: "test@invalid.example.com", err: "invalid_email_dns"},
		{email: "test@no.such.email.host.supabase.io", err: "invalid_email_dns"},

		// test blocked mx records
		{email: "test@hotmail.com", err: "invalid_email_mx"},

		// this low timeout should simulate a dns timeout, which should
		// not be treated as an invalid email.
		{email: "validemail@probablyaaaaaaaanotarealdomain.com",
			timeout: time.Millisecond},

		// likewise for a valid email
		{email: "support@supabase.io", timeout: time.Millisecond},
	}

	cfg := conf.MailerConfiguration{
		EmailValidationExtended:       true,
		EmailValidationServiceURL:     "",
		EmailValidationServiceHeaders: "",
		EmailValidationBlockedMX:      `["hotmail-com.olc.protection.outlook.com"]`,
	}

	// Ensure the BlockedMX transformation occurs by calling Validate
	if err := cfg.Validate(); err != nil {
		t.Fatalf("failed to validate MailerConfiguration: %v", err)
	}

	ev := newEmailValidator(cfg)

	for idx, tc := range cases {
		func(timeout time.Duration) {
			if timeout == 0 {
				timeout = validateEmailTimeout
			}

			ctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			now := time.Now()
			err := ev.Validate(ctx, tc.email)
			dur := time.Since(now)
			if max := timeout + (time.Millisecond * 50); max < dur {
				t.Fatal("timeout was not respected")
			}

			t.Logf("tc #%v - email %q", idx, tc.email)
			if tc.err != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.err)
				return
			}
			require.NoError(t, err)

		}(tc.timeout)
	}
}
