package query

import (
	"maps"
	"slices"

	"github.com/supabase-community/scim-go/pkg/core"
)

const (
	ValueAttribute       = "value"
	displayNameAttribute = "displayName"
)

type kind int

const (
	single kind = iota
	multi
	inverse
)

type Edge struct {
	Type      string
	Attribute string
}

type Reference struct {
	attribute *core.Attribute
	uri       core.SchemaURI
	kind      kind
	targets   []string
	via       Edge
	nested    bool
}

func References(resourceType string, schemas core.Schemas, inverses map[Edge]Edge) []Reference {
	references := []Reference{}
	for _, schema := range schemas {
		uri := core.SchemaURI("")
		if schemas.IsExtension(schema) {
			uri = schema.ID
		}
		for _, attribute := range schema.Attributes {
			targets := resourceTypes(attribute)
			if len(targets) == 0 {
				continue
			}
			ref := Reference{attribute: attribute, uri: uri, targets: targets}
			self := Edge{resourceType, ref.Path()}
			via, inverted := inverses[self]
			switch {
			case inverted:
				ref.kind, ref.via = inverse, via
			case attribute.Mutability == core.MutabilityReadOnly:
				continue
			case attribute.MultiValued:
				ref.kind, ref.nested = multi, slices.Contains(slices.Collect(maps.Values(inverses)), self)
			default:
				ref.kind = single
			}
			references = append(references, ref)
		}
	}
	return references
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

func (r Reference) Name() string {
	return r.attribute.Name
}

func (r Reference) Path() string {
	if r.uri == "" {
		return r.Name()
	}
	return string(r.uri) + ":" + r.Name()
}
