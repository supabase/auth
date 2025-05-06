package v0hooks

import (
	"net/http"

	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/storage"
)

type Service interface {
	Enabled(name Name) bool

	InvokeHook(
		conn *storage.Connection,
		r *http.Request,
		input, output any,
	) error

	RunHTTPHook(
		r *http.Request,
		hookConfig conf.ExtensibilityPointConfiguration,
		input any,
	) ([]byte, error)
}
