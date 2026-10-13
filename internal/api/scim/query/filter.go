package query

import (
	"strconv"

	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/filter"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
)

func (r Reference) Leaf(definition *core.Attribute, op filter.Operator, value any) (Clause, error) {
	if r.kind != multi {
		return nil, unfilterable(r, definition)
	}
	if op != filter.OpPresent {
		return match(r, definition, op, value)
	}
	if _, ok := edgeColumns[definition.Name]; !ok && definition.Name != r.Name() {
		return nil, unfilterable(r, definition)
	}
	return predicate{text: "TRUE"}, nil
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

var edgeColumns = map[string]string{ValueAttribute: "edge.target_id", "type": "lower(target.resource_type)"}

func match(ref Reference, definition *core.Attribute, op filter.Operator, value any) (Clause, error) {
	text, _ := value.(string)
	if op != filter.OpEquals && op != filter.OpNotEquals {
		return nil, scimerrors.ErrInvalidFilter(strconv.Quote(ref.Name()+"."+definition.Name) + " supports only eq and ne")
	}
	sign := comparisons[op]
	column, ok := edgeColumns[definition.Name]
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
