package query

import (
	"maps"
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

func NewResource(resourceType string, schemas core.Schemas, locations map[string]string, inverses map[Edge]Edge) Resource {
	return Resource{
		Type:       resourceType,
		schemas:    schemas,
		references: referencesOf(resourceType, schemas, inverses),
		location:   locations[resourceType],
	}
}

func (r Resource) Location() string {
	return r.location
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
		if requested.Returns(ref.Name()) {
			parts = append(parts, projection{}.part(ref))
		}
	}
	return "json_build_array(" + strings.Join(parts, ", ") + ")"
}

func (r Resource) where(expression string) (Clause, error) {
	if expression == "" {
		return nil, nil
	}
	return protocol.Filter(r.schemas, expression, evaluator{r.schemas, r.location, r.references})
}

func referencesOf(resourceType string, schemas core.Schemas, inverses map[Edge]Edge) []Reference {
	references := []Reference{}
	for _, attribute := range schemas.Base().Attributes {
		targets := resourceTypes(attribute)
		if len(targets) == 0 {
			continue
		}
		ref := Reference{attribute: attribute, targets: targets}
		self := Edge{resourceType, ref.Name()}
		via, inverted := inverses[self]
		switch {
		case inverted:
			ref.kind, ref.via = inverse, via
		case attribute.Mutability == core.MutabilityReadOnly:
			continue
		case attribute.MultiValued:
			ref.kind, ref.nested = multi, slices.Contains(slices.Collect(maps.Values(inverses)), self)
		default:
			continue
		}
		references = append(references, ref)
	}
	return references
}
