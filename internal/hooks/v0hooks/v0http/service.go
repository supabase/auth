package v0http

import (
	"context"

	"github.com/supabase/auth/internal/conf"
)

type Service interface {
	HTTPDispatch(
		ctx context.Context,
		cfg conf.ExtensibilityPointConfiguration,
		req any,
		res any,
	) error

	RunHTTPHook(
		ctx context.Context,
		hookConfig conf.ExtensibilityPointConfiguration,
		input any,
	) ([]byte, error)
}
