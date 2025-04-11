package hooks

import (
	"net/http"

	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/hooks/v0hooks"
	"github.com/supabase/auth/internal/storage"
)

type Manager struct {
	v0mgr *v0hooks.Manager
}

func NewManager(
	db *storage.Connection,
	config *conf.GlobalConfiguration,
) *Manager {
	return &Manager{
		v0mgr: v0hooks.NewManager(db, config),
	}
}

func (o *Manager) InvokeHook(
	conn *storage.Connection,
	r *http.Request,
	input, output any,
) error {
	return o.v0mgr.InvokeHook(conn, r, input, output)
}

func (o *Manager) RunHTTPHook(
	r *http.Request,
	hookConfig conf.ExtensibilityPointConfiguration,
	input any,
) ([]byte, error) {
	return o.v0mgr.RunHTTPHook(r, hookConfig, input)
}
