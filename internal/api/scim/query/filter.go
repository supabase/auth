package query

import (
	"strconv"
	"uuid"

	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/filter"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
)

func (r Reference) Leaf(definition *core.Attribute, op filter.Operator, value any) (Clause, error) {
	if r.kind == single {
		return nil, unfilterable(r, definition)
	}
	if op != filter.OpPresent {
		return match(r, definition, op, value)
	}
	if _, ok := r.columns()[definition.Name]; !ok && definition.Name != r.Name() {
		return nil, unfilterable(r, definition)
	}
	return predicate{text: "TRUE"}, nil
}

func (r Reference) Exists(provider uuid.UUID, inner string, args []any) (string, []any) {
	if r.kind == multi {
		return r.edgeExists(inner, args)
	}
	return r.inverseExists(provider, inner, args)
}

func (r Reference) shown() string {
	for _, name := range []string{"display", displayNameAttribute} {
		if sub := r.attribute.SubAttribute(name); sub != nil {
			return sub.Name
		}
	}
	return ""
}

func (r Reference) resolves(sub string) bool {
	return r.kind != single || sub == r.shown()
}

func (r Reference) computed(sub string) bool {
	return r.kind != single || sub != ValueAttribute
}

func (r Reference) columns() map[string]string {
	switch r.kind {
	case multi:
		return map[string]string{ValueAttribute: "edge.target_id", "type": "lower(target.resource_type)"}
	case inverse:
		return map[string]string{ValueAttribute: "chain.id"}
	}
	return nil
}

func match(ref Reference, definition *core.Attribute, op filter.Operator, value any) (Clause, error) {
	text, _ := value.(string)
	if op != filter.OpEquals && op != filter.OpNotEquals {
		return nil, scimerrors.ErrInvalidFilter(strconv.Quote(ref.Name()+"."+definition.Name) + " supports only eq and ne")
	}
	sign := comparisons[op]
	column, ok := ref.columns()[definition.Name]
	if !ok {
		return nil, unfilterable(ref, definition)
	}
	if definition.Name != ValueAttribute {
		return predicate{column + sign + "lower(?)", []any{text}}, nil
	}
	return uuidPredicate(column, sign, op, text), nil
}

func unfilterable(ref Reference, definition *core.Attribute) error {
	return scimerrors.ErrInvalidFilter(strconv.Quote(ref.Name()+"."+definition.Name) + " cannot be filtered")
}
