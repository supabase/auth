package scim

import (
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
)

type ResourceSpec[T core.Resource] struct {
	Path     string
	Schema   *core.Schema
	New      func() T
	Validate func(T) *protocol.Error
	Location func(T) string
}
