package query

import (
	"maps"
	"slices"
	"strings"

	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/patch"
	"github.com/supabase-community/scim-go/pkg/protocol"
)

type Search struct {
	Where     Clause
	Order     string
	OrderArgs []any
}

type Resource struct {
	schemas    core.Schemas
	references []Reference
	locations  map[string]string
	location   string
}

func NewResource(resourceType string, schemas core.Schemas, locations map[string]string, inverses map[Edge]Edge) Resource {
	return Resource{
		schemas:    schemas,
		references: referencesOf(resourceType, schemas, inverses),
		locations:  locations,
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
	if p, ok := where.(prefix); ok && request.SortBy == "" {
		sorted := *request
		sorted.SortBy = p.attribute
		request = &sorted
	}
	order, args, err := r.order(request)
	return Search{Where: where, Order: order, OrderArgs: args}, err
}

func (r Resource) Select(projection protocol.Projection) string {
	return r.SelectTouched(r.returned(projection))
}

func (r Resource) SelectTouched(touched Touched) string {
	parts := []string{}
	for _, ref := range r.references {
		if only, ok := touched[ref.Path()]; ok {
			parts = append(parts, projection{r.locations, only}.part(ref))
		}
	}
	return "json_build_array(" + strings.Join(parts, ", ") + ")"
}

func (r Resource) Touches(ops []patch.Operation) Touched {
	touched := Touched{}
	for _, op := range ops {
		if !touched.op(r.references, op) {
			return nil
		}
	}
	return touched
}

func (r Resource) Returns(projection protocol.Projection) bool {
	return len(r.returned(projection)) > 0
}

func (r Resource) returned(projection protocol.Projection) Touched {
	touched := Touched{}
	for _, ref := range r.references {
		if projection.Returns(ref.Path()) {
			touched[ref.Path()] = nil
		}
	}
	return touched
}

func (r Resource) where(expression string) (Clause, error) {
	if expression == "" {
		return nil, nil
	}
	return protocol.Filter(r.schemas, expression, evaluator{r.schemas, r.location, r.references})
}

func referencesOf(resourceType string, schemas core.Schemas, inverses map[Edge]Edge) []Reference {
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
