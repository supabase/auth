package templatemailer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

// recordedMail is a single mail delivery observed by the test-only client
// below.
type recordedMail struct {
	To      string
	Subject string
	Body    string
	Type    string
}

// recordingClient is a test-only mailer.Client that records every delivery
// (most importantly the recipient). templatemailer.Mailer keeps its client in
// an unexported field, but since it is injected through New(cfg, mc, tc) a
// test can supply its own implementation without any production change.
type recordingClient struct {
	mu    sync.Mutex
	mails []recordedMail
}

func (c *recordingClient) Mail(
	ctx context.Context,
	to string,
	subject string,
	body string,
	headers map[string][]string,
	typ string,
) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.mails = append(c.mails, recordedMail{To: to, Subject: subject, Body: body, Type: typ})
	return nil
}

func (c *recordingClient) recipients() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(c.mails))
	for _, m := range c.mails {
		out = append(out, m.To)
	}
	return out
}

// EmailChangeMail must not send anything to user.EmailChange when otpNew is
// empty. That is the case when the requested address is already registered
// to another account: exactly one message is produced and it goes to the
// user's current email.
func TestEmailChangeMailSkipsTakenNewAddress(t *testing.T) {
	externalURL, err := url.Parse("http://localhost:9999")
	require.NoError(t, err)

	cfg := &conf.GlobalConfiguration{SiteURL: "http://localhost:9999"}
	cfg.Mailer.SecureEmailChangeEnabled = true

	client := &recordingClient{}
	m := New(cfg, client, NewCache())

	user := &models.User{
		Email:       storage.NullString("current@example.com"),
		EmailChange: "taken@example.com",
	}

	r := httptest.NewRequest(http.MethodPost, "http://localhost/", nil)

	// otpNew is empty: the new (taken) address must be left out entirely
	require.NoError(t, m.EmailChangeMail(r, user, "", "654321", "", externalURL))

	mails := client.recipients()
	require.Len(t, mails, 1, "expected exactly one message when otpNew is empty")
	require.Equal(t, "current@example.com", mails[0],
		"the message must go to the user's current email")
	require.NotEqual(t, "taken@example.com", mails[0],
		"no message must be sent to the taken address in user.EmailChange")
}

// With an otp for the new address, both messages are produced: one for the
// new address and one for the current address (secure email change enabled).
func TestEmailChangeMailSendsToBothAddressesWhenOtpNewIsSet(t *testing.T) {
	externalURL, err := url.Parse("http://localhost:9999")
	require.NoError(t, err)

	cfg := &conf.GlobalConfiguration{SiteURL: "http://localhost:9999"}
	cfg.Mailer.SecureEmailChangeEnabled = true

	client := &recordingClient{}
	m := New(cfg, client, NewCache())

	user := &models.User{
		Email:       storage.NullString("current@example.com"),
		EmailChange: "new@example.com",
	}

	r := httptest.NewRequest(http.MethodPost, "http://localhost/", nil)

	require.NoError(t, m.EmailChangeMail(r, user, "123456", "654321", "", externalURL))

	mails := client.recipients()
	require.Len(t, mails, 2, "expected one message per address in dual confirmation mode")
	require.ElementsMatch(t, []string{"new@example.com", "current@example.com"}, mails)
}
