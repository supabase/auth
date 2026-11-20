package templatemailer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/mailer"
	"github.com/supabase/auth/internal/mailer/validateclient"
	"github.com/supabase/auth/internal/models"
)

func TestTemplateHeaders(t *testing.T) {
	cases := []struct {
		from string
		typ  string
		exp  map[string][]string
	}{
		{
			from: `{"x-supabase-project-ref": ["abcjrhohrqmvcpjpsyzc"]}`,
			typ:  "OTHER-TYPE",
			exp: map[string][]string{
				"x-supabase-project-ref": {"abcjrhohrqmvcpjpsyzc"},
			},
		},

		{
			from: `{"X-Test-A": ["test-a", "test-b"], "X-Test-B": ["test-c", "abc $messageType"]}`,
			typ:  "TEST-MESSAGE-TYPE",
			exp: map[string][]string{
				"X-Test-A": {"test-a", "test-b"},
				"X-Test-B": {"test-c", "abc TEST-MESSAGE-TYPE"},
			},
		},

		{
			from: `{"X-Test-A": ["test-a", "test-b"], "X-Test-B": ["test-c", "abc $messageType"]}`,
			typ:  "OTHER-TYPE",
			exp: map[string][]string{
				"X-Test-A": {"test-a", "test-b"},
				"X-Test-B": {"test-c", "abc OTHER-TYPE"},
			},
		},

		{
			from: `{"X-Test-A": ["test-a", "test-b"], "X-Test-B": ["test-c", "abc $messageType"], "x-supabase-project-ref": ["abcjrhohrqmvcpjpsyzc"]}`,
			typ:  "OTHER-TYPE",
			exp: map[string][]string{
				"X-Test-A":               {"test-a", "test-b"},
				"X-Test-B":               {"test-c", "abc OTHER-TYPE"},
				"x-supabase-project-ref": {"abcjrhohrqmvcpjpsyzc"},
			},
		},
	}
	for _, tc := range cases {
		mailer := New(&conf.GlobalConfiguration{
			SMTP: conf.SMTPConfiguration{
				Headers: tc.from,
			},
		}, nil, nil)

		require.NoError(t, mailer.cfg.SMTP.Validate())

		hdrs := mailer.Headers(mailer.cfg, tc.typ)
		require.Equal(t, hdrs, tc.exp)
	}
}

// testMailClient is a mailer.Client that records the addresses it sent to
// and, like the validating client, rejects the addresses in invalid. A
// rejected Mail call waits for another mail to go out (or a second to pass)
// before it returns, so the result does not depend on which of the two email
// change mails is handled first.
type testMailClient struct {
	invalid map[string]bool

	mu      sync.Mutex
	sent    []string
	sentOne chan struct{}
}

func newTestMailClient(invalid ...string) *testMailClient {
	c := &testMailClient{
		invalid: make(map[string]bool, len(invalid)),
		sentOne: make(chan struct{}),
	}
	for _, addr := range invalid {
		c.invalid[addr] = true
	}
	return c
}

func (c *testMailClient) Mail(
	ctx context.Context,
	to string,
	subject string,
	body string,
	headers map[string][]string,
	typ string,
) error {
	if c.invalid[to] {
		select {
		case <-c.sentOne:
		case <-time.After(time.Second):
		}
		return validateclient.ErrInvalidEmailDNS
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.sent) == 0 {
		close(c.sentOne)
	}
	c.sent = append(c.sent, to)
	return nil
}

func (c *testMailClient) sentTo() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	sent := append([]string{}, c.sent...)
	sort.Strings(sent)
	return sent
}

// validatingTestMailClient is a testMailClient that can also check an
// address without sending to it.
type validatingTestMailClient struct {
	*testMailClient
}

func (c *validatingTestMailClient) Validate(ctx context.Context, to string) error {
	if c.invalid[to] {
		return validateclient.ErrInvalidEmailDNS
	}
	return nil
}

func TestEmailChangeMailValidatesBeforeSending(t *testing.T) {
	const (
		currentEmail = "current@outlook.com"
		newEmail     = "new@outlook.com"
		blockedEmail = "someone@example.com"
	)

	cfg := &conf.GlobalConfiguration{
		SiteURL: "https://example.com",
		Mailer: conf.MailerConfiguration{
			SecureEmailChangeEnabled: true,
			EmailValidationExtended:  true,
		},
	}
	externalURL, err := url.Parse("https://auth.example.com")
	require.NoError(t, err)

	send := func(t *testing.T, mc mailer.Client, current, change string) error {
		user, err := models.NewUser("", current, "", "authenticated", nil)
		require.NoError(t, err)
		user.EmailChange = change

		req := httptest.NewRequest(http.MethodPut, "/user", nil)
		return New(cfg, mc, NewCache()).EmailChangeMail(
			req, user, "111111", "222222", "", externalURL)
	}

	cases := []struct {
		desc    string
		current string
		change  string
		invalid string
		sent    []string
	}{
		{
			desc:    "new address is rejected",
			current: currentEmail,
			change:  blockedEmail,
			invalid: blockedEmail,
			sent:    []string{},
		},
		{
			desc:    "current address is rejected",
			current: blockedEmail,
			change:  newEmail,
			invalid: blockedEmail,
			sent:    []string{},
		},
		{
			desc:    "both addresses are accepted",
			current: currentEmail,
			change:  newEmail,
			sent:    []string{currentEmail, newEmail},
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			mc := newTestMailClient()
			if tc.invalid != "" {
				mc = newTestMailClient(tc.invalid)
			}

			err := send(t, &validatingTestMailClient{mc}, tc.current, tc.change)
			if tc.invalid != "" {
				require.ErrorIs(t, err, validateclient.ErrInvalidEmailDNS)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tc.sent, mc.sentTo())
		})

		// The same through the client the server uses: example.com is on
		// its list of invalid hosts and outlook.com on its allow list, so
		// neither result needs a DNS lookup.
		t.Run(tc.desc+" (validateclient)", func(t *testing.T) {
			mc := newTestMailClient()

			err := send(t, validateclient.New(cfg, mc), tc.current, tc.change)
			if tc.invalid != "" {
				require.ErrorIs(t, err, validateclient.ErrInvalidEmailDNS)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tc.sent, mc.sentTo())
		})
	}
}
