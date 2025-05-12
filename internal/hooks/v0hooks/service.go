package v0hooks

import (
	"context"
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
