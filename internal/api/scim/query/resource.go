package query

import (
	"slices"
	"strings"

	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
)

type Search struct {
	Where     Clause
	Order     string
	OrderArgs []any
}

type Resource struct {
	Type       string
	schemas    core.Schemas
	references []Reference
	location   string
}

func NewResource(schemas core.Schemas, location string) Resource {
	return Resource{
		Type:       string(schemas.Base().Name),
		schemas:    schemas,
		references: referencesOf(schemas),
		location:   location,
	}
}

func (r Resource) References() []Reference {
	return r.references
}

func (r Resource) Search(request *protocol.SearchRequest) (Search, error) {
	where, err := r.where(request.Filter)
	if err != nil {
		return Search{}, err
	}
	order, args, err := r.order(request)
	return Search{Where: where, Order: order, OrderArgs: args}, err
}

func (r Resource) Select(requested protocol.Projection) string {
	parts := []string{}
	for _, ref := range r.references {
		if requested.Returns(ref.Name) {
			parts = append(parts, ref.selection())
		}
	}
	return "json_build_array(" + strings.Join(parts, ", ") + ")"
}

func (r Resource) where(expression string) (Clause, error) {
	if expression == "" {
		return nil, nil
	}
	return protocol.Filter(r.schemas, expression, evaluator{r})
}

func referencesOf(schemas core.Schemas) []Reference {
	references := []Reference{}
	for _, attribute := range (core.Schemas{schemas.Base()}).ReferenceAttributes() {
		ref := Reference{attribute}
		if ref.Inverse() || attribute.MultiValued {
			references = append(references, ref)
		}
	}
	return references
}

func (r Resource) lookup(top *core.Attribute) *Reference {
	index := slices.IndexFunc(r.references, func(ref Reference) bool { return ref.Attribute == top })
	if index < 0 {
		return nil
	}
	return &r.references[index]
}
