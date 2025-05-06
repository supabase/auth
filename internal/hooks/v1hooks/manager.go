package v1hooks

import (
	"context"

	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/hooks/dispatch"
	"github.com/supabase/auth/internal/hooks/v0hooks"
	"github.com/supabase/auth/internal/storage"
)

type Manager struct {
	cfg *conf.HookConfiguration
	dr  dispatch.Service
}

func New(
	cfg *conf.HookConfiguration,
	dr dispatch.Service,
) *Manager {
	o := &Manager{
		cfg: cfg,
		dr:  dr,
	}
	return o
}

func (o *Manager) Enabled(name v0hooks.Name) bool {
	if cfg, ok := configByName(o.cfg, name); ok {
		return cfg.Enabled
	}
	return false
}

func (o *Manager) BeforeUserCreated(
	ctx context.Context,
	tx *storage.Connection,
	req *BeforeUserCreatedRequest,
	res *BeforeUserCreatedResponse,
) error {
	return o.dr.Dispatch(ctx, &o.cfg.BeforeUserCreated, tx, req, res)
}

func (o *Manager) AfterUserCreated(
	ctx context.Context,
	tx *storage.Connection,
	req *AfterUserCreatedRequest,
	res *AfterUserCreatedResponse,
) error {
	return o.dr.Dispatch(ctx, &o.cfg.AfterUserCreated, tx, req, res)
}

func configByName(
	cfg *conf.HookConfiguration,
	name v0hooks.Name,
) (*conf.ExtensibilityPointConfiguration, bool) {
	switch name {
	case BeforeUserCreated:
		return &cfg.BeforeUserCreated, true
	case AfterUserCreated:
		return &cfg.AfterUserCreated, true
	default:
		return nil, false
	}
}
