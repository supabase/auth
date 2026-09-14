package scim

import (
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
)

type ResourceSpec[T core.Resource] struct {
	Path     string
	Schema   *core.Schema
	New      func() T
	Validate func(T) *scimerrors.Error
	Location func(T) string
}
