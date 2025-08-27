package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/e2e"
	"github.com/supabase/auth/internal/mailer"
)

func TestNewLimiterOptions(t *testing.T) {
	cfg := &conf.GlobalConfiguration{}
	cfg.ApplyDefaults()

	rl := NewLimiterOptions(cfg)
	assert.NotNil(t, rl.Email)
	assert.NotNil(t, rl.Phone)
	assert.NotNil(t, rl.Signups)
	assert.NotNil(t, rl.AnonymousSignIns)
	assert.NotNil(t, rl.Recover)
	assert.NotNil(t, rl.Resend)
	assert.NotNil(t, rl.MagicLink)
	assert.NotNil(t, rl.Otp)
	assert.NotNil(t, rl.Token)
	assert.NotNil(t, rl.Verify)
	assert.NotNil(t, rl.User)
	assert.NotNil(t, rl.FactorVerify)
	assert.NotNil(t, rl.FactorChallenge)
	assert.NotNil(t, rl.SSO)
	assert.NotNil(t, rl.SAMLAssertion)
}

func TestMailerOptions(t *testing.T) {
	globalCfg := e2e.Must(e2e.Config())
	conn := e2e.Must(e2e.Conn(globalCfg))

	sentinelMailer := mailer.NewMailClient(globalCfg)
	mailerOpts := &MailerOptions{MailerClientFunc: func() mailer.MailClient {
		return sentinelMailer
	}}
	a := NewAPIWithVersion(globalCfg, conn, apiTestVersion, mailerOpts)

	got := a.mailerClientFunc()
	require.Equal(t, sentinelMailer, got)
}
