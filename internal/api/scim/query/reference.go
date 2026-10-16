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
