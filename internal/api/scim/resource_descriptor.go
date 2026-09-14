package scim

import (
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
)

type ResourceDescriptor[T core.Resource] struct {
	Schema   *core.Schema
	New      func() T
	Validate func(T) *scimerrors.Error
	Location func(T) string
}
