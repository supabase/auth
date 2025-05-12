package hooks

import (
	"context"
	"net/http"

	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/hooks/hookhttp"
	"github.com/supabase/auth/internal/hooks/hookpgfunc"
	"github.com/supabase/auth/internal/hooks/v0hooks"
	"github.com/supabase/auth/internal/storage"
)

type Manager struct {
	v0svc v0hooks.Service
}

func New(
	globalConfig *conf.GlobalConfiguration,
	db *storage.Connection,
) *Manager {
	httpDr := hookhttp.New()
	pgfuncDr := hookpgfunc.New(db)
	v0svc := v0hooks.New(globalConfig, httpDr, pgfuncDr)
	return NewFromService(v0svc)
}

func NewFromService(
	v0svc v0hooks.Service,
) *Manager {
	return &Manager{
		v0svc: v0svc,
	}
}

func (o *Manager) Enabled(name v0hooks.Name) bool {
	return o.v0svc.Enabled(name)
}

func (o *Manager) InvokeHook(
	conn *storage.Connection,
	r *http.Request,
	input, output any,
) error {
	return o.v0svc.InvokeHook(conn, r, input, output)
}

func (o *Manager) RunHTTPHook(
	r *http.Request,
	hookConfig conf.ExtensibilityPointConfiguration,
	input any,
) ([]byte, error) {
	return o.v0svc.RunHTTPHook(r, hookConfig, input)
}

func (o *Manager) BeforeUserCreated(
	ctx context.Context,
	tx *storage.Connection,
	req *v0hooks.BeforeUserCreatedRequest,
	res *v0hooks.BeforeUserCreatedResponse,
) error {
	return o.v0svc.BeforeUserCreated(ctx, tx, req, res)
}

func (o *Manager) AfterUserCreated(
	ctx context.Context,
	tx *storage.Connection,
	req *v0hooks.AfterUserCreatedRequest,
	res *v0hooks.AfterUserCreatedResponse,
) error {
	return o.v0svc.AfterUserCreated(ctx, tx, req, res)
}
