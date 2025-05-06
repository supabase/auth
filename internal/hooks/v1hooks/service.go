package v1hooks

import (
	"context"

	"github.com/supabase/auth/internal/hooks/v0hooks"
	"github.com/supabase/auth/internal/storage"
)

type Service interface {
	Enabled(name v0hooks.Name) bool

	BeforeUserCreated(
		ctx context.Context,
		tx *storage.Connection,
		req *BeforeUserCreatedRequest,
		res *BeforeUserCreatedResponse,
	) error

	AfterUserCreated(
		ctx context.Context,
		tx *storage.Connection,
		req *AfterUserCreatedRequest,
		res *AfterUserCreatedResponse,
	) error
}
