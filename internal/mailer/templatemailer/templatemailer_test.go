package templatemailer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
)

type captureClient struct {
	subject string
}

func (c *captureClient) Mail(_ context.Context, _ string, subject string, _ string, _ map[string][]string, _ string) error {
	c.subject = subject
	return nil
}

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

func TestNotificationMailSiteURL(t *testing.T) {
	const siteURL = "https://example.com"

	user := &models.User{}
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	cases := []struct {
		name string
		subj func(cfg *conf.GlobalConfiguration)
		send func(m *Mailer) error
	}{
		{
			name: "PasswordChangedNotificationMail",
			subj: func(cfg *conf.GlobalConfiguration) {
				cfg.Mailer.Subjects.PasswordChangedNotification = "{{ .SiteURL }}"
			},
			send: func(m *Mailer) error { return m.PasswordChangedNotificationMail(r, user) },
		},
		{
			name: "EmailChangedNotificationMail",
			subj: func(cfg *conf.GlobalConfiguration) {
				cfg.Mailer.Subjects.EmailChangedNotification = "{{ .SiteURL }}"
			},
			send: func(m *Mailer) error { return m.EmailChangedNotificationMail(r, user, "") },
		},
		{
			name: "PhoneChangedNotificationMail",
			subj: func(cfg *conf.GlobalConfiguration) {
				cfg.Mailer.Subjects.PhoneChangedNotification = "{{ .SiteURL }}"
			},
			send: func(m *Mailer) error { return m.PhoneChangedNotificationMail(r, user, "") },
		},
		{
			name: "IdentityLinkedNotificationMail",
			subj: func(cfg *conf.GlobalConfiguration) {
				cfg.Mailer.Subjects.IdentityLinkedNotification = "{{ .SiteURL }}"
			},
			send: func(m *Mailer) error { return m.IdentityLinkedNotificationMail(r, user, "") },
		},
		{
			name: "IdentityUnlinkedNotificationMail",
			subj: func(cfg *conf.GlobalConfiguration) {
				cfg.Mailer.Subjects.IdentityUnlinkedNotification = "{{ .SiteURL }}"
			},
			send: func(m *Mailer) error { return m.IdentityUnlinkedNotificationMail(r, user, "") },
		},
		{
			name: "MFAFactorEnrolledNotificationMail",
			subj: func(cfg *conf.GlobalConfiguration) {
				cfg.Mailer.Subjects.MFAFactorEnrolledNotification = "{{ .SiteURL }}"
			},
			send: func(m *Mailer) error { return m.MFAFactorEnrolledNotificationMail(r, user, "") },
		},
		{
			name: "MFAFactorUnenrolledNotificationMail",
			subj: func(cfg *conf.GlobalConfiguration) {
				cfg.Mailer.Subjects.MFAFactorUnenrolledNotification = "{{ .SiteURL }}"
			},
			send: func(m *Mailer) error { return m.MFAFactorUnenrolledNotificationMail(r, user, "") },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cc := &captureClient{}
			cfg := &conf.GlobalConfiguration{SiteURL: siteURL}
			tc.subj(cfg)
			m := New(cfg, cc, NewCache())
			require.NoError(t, tc.send(m))
			require.Equal(t, siteURL, cc.subject)
		})
	}
}
