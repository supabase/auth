package query

import (
	"github.com/supabase-community/scim-go/pkg/core"
)

const ValueAttribute = "value"

type Reference struct {
	core.ReferenceAttribute
}

func (r Reference) Inverse() bool {
	return r.InverseOf != ""
}

func (r Reference) Types() []string {
	types := make([]string, len(r.Targets))
	for i, t := range r.Targets {
		types[i] = string(t)
	}
	return types
}
