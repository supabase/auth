package hookpgfunc

import (
	"context"

	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/storage"
)

type Service interface {
	PGFuncDispatch(
		ctx context.Context,
		cfg conf.ExtensibilityPointConfiguration,
		tx *storage.Connection,
		req any,
		res any,
	) error

	RunPostgresHook(
		ctx context.Context,
		hookConfig conf.ExtensibilityPointConfiguration,
		tx *storage.Connection,
		input any,
	) ([]byte, error)
}
