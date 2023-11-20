package api

import (
	"github.com/supabase/gotrue/internal/conf"
	"time"
)

type AuthHook struct {
	*conf.HookConfiguration
	payload []byte
}

const (
	defaultTimeout     = time.Second * 2
	defaultHookRetries = 3
)

type HookType string

const (
	PostgresHook HookType = "postgres"
)

func (a *AuthHook) trigger() error {
	// Parse URI object

	// switch between Postgres Hook and HTTP Hook, pass in URI
	return nil
}

func (a *AuthHook) triggerPostgresHook() error {

	return nil
}
