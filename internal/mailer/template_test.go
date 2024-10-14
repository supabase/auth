package mailer

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
)

func TestTemplateHeaders(t *testing.T) {
	mailer := TemplateMailer{
		Config: &conf.GlobalConfiguration{
			SMTP: conf.SMTPConfiguration{
				Headers: `{"X-Test-A": ["test-a", "test-b"], "X-Test-B": ["test-c", "abc $messageType"]}`,
			},
		},
	}

	require.NoError(t, mailer.Config.SMTP.Validate())

	require.Equal(t, mailer.Headers("TEST-MESSAGE-TYPE"), map[string][]string{
		"X-Test-A": {"test-a", "test-b"},
		"X-Test-B": {"test-c", "abc TEST-MESSAGE-TYPE"},
	})

	require.Equal(t, mailer.Headers("OTHER-TYPE"), map[string][]string{
		"X-Test-A": {"test-a", "test-b"},
		"X-Test-B": {"test-c", "abc OTHER-TYPE"},
	})
}
