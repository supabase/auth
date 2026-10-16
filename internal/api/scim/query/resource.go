package query

import (
	"slices"

	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/store"
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

func (r Resource) Search(request *protocol.SearchRequest) (Search, error) {
	where, err := r.where(request.Filter)
	if err != nil {
		return Search{}, err
	}
	order, args, err := r.order(request)
	return Search{Where: where, Order: order, OrderArgs: args}, err
}

func (r Resource) where(expression string) (Clause, error) {
	if expression == "" {
		return nil, nil
	}
	return protocol.Filter(r.schemas, expression, evaluator{r})
}

func referencesOf(schemas core.Schemas) []Reference {
	references := []Reference{}
	for _, ref := range store.ReferencesOf(core.Schemas{schemas.Base()}) {
		if !ref.Soft() {
			references = append(references, Reference{ref})
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
