package query

import (
	"github.com/supabase-community/scim-go/pkg/core"
)

const ValueAttribute = "value"

type kind int

const (
	multi kind = iota
	inverse
)

type Edge struct {
	Type      string
	Attribute string
}

type Reference struct {
	attribute *core.Attribute
	kind      kind
	targets   []string
	via       Edge
	nested    bool
}

func (r Reference) Name() string {
	return r.attribute.Name
}

func (r Reference) Targets() []string {
	if r.kind != multi {
		return nil
	}
	return r.targets
}

func (r Reference) Nested() bool {
	return r.nested
}

func resourceTypes(attribute *core.Attribute) []string {
	ref := attribute.SubAttribute("$ref")
	if attribute.Type != core.TypeComplex || ref == nil {
		return nil
	}
	types := []string{}
	for _, t := range ref.ReferenceTypes {
		if t != core.ReferenceExternal && t != core.ReferenceURI {
			types = append(types, string(t))
		}
	}
	return types
}
