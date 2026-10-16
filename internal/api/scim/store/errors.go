package store

import (
	"github.com/supabase-community/scim-go/pkg/scimerrors"
)

func notFound() error {
	return scimerrors.ErrNotFound("Not found")
}
