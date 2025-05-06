package hooks

import (
	"context"
	"net/http"

	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/hooks/dispatch"
	"github.com/supabase/auth/internal/hooks/v0hooks"
	"github.com/supabase/auth/internal/hooks/v0hooks/v0http"
	"github.com/supabase/auth/internal/hooks/v0hooks/v0pgfunc"
	"github.com/supabase/auth/internal/hooks/v1hooks"
	"github.com/supabase/auth/internal/storage"
)

type Manager struct {
	v0svc v0hooks.Service
	v1svc v1hooks.Service
}

func New(
	globalConfig *conf.GlobalConfiguration,
	db *storage.Connection,
) *Manager {
	httpDr := v0http.New()
	pgfuncDr := v0pgfunc.New(db)
	dr := dispatch.New(httpDr, pgfuncDr)
	v0svc := v0hooks.New(globalConfig, httpDr, pgfuncDr)
	v1svc := v1hooks.New(&globalConfig.Hook, dr)
	return NewFromServices(v0svc, v1svc)
}

func NewFromServices(
	v0svc v0hooks.Service,
	v1svc v1hooks.Service,
) *Manager {
	return &Manager{
		v0svc: v0svc,
		v1svc: v1svc,
	}
}

func (o *Manager) Enabled(name v0hooks.Name) bool {
	return o.v0svc.Enabled(name) || o.v1svc.Enabled(name)
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
	req *v1hooks.BeforeUserCreatedRequest,
	res *v1hooks.BeforeUserCreatedResponse,
) error {
	return o.v1svc.BeforeUserCreated(ctx, tx, req, res)
}

func (o *Manager) AfterUserCreated(
	ctx context.Context,
	tx *storage.Connection,
	req *v1hooks.AfterUserCreatedRequest,
	res *v1hooks.AfterUserCreatedResponse,
) error {
	return o.v1svc.AfterUserCreated(ctx, tx, req, res)
}
