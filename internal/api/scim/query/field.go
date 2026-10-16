package query

import (
	"strconv"

	"github.com/supabase-community/scim-go/pkg/filter"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase-community/scim-go/pkg/server"
)

var narrowing = map[filter.Operator]bool{
	filter.OpEquals:     true,
	filter.OpStartsWith: true,
	filter.OpContains:   true,
	filter.OpEndsWith:   true,
}

type field struct {
	attribute *protocol.Attribute
	name      string
	path      path
	ref       *reference
}

func (f field) isColumn() bool {
	_, ok := columns[f.name]
	return ok
}

func (f field) columnMatch(op filter.Operator, value any) (Clause, error) {
	sign, ok := comparisons[op]
	if !ok {
		return nil, scimerrors.ErrInvalidFilter(strconv.Quote(f.name) + " supports only eq, ne, gt, ge, lt and le")
	}
	text, _ := value.(string)
	switch f.name {
	case "id", metaLocation:
		return uuidPredicate("id", op, text), nil
	case "meta.version":
		at, ok := server.ParseWeakETag(text)
		if !ok {
			return boolean(op == filter.OpNotEquals), nil
		}
		return predicate{"updated_at" + sign + "?", []any{at}}, nil
	}
	return predicate{columns[f.name] + sign + "?", []any{value}}, nil
}

func (f field) present() (Clause, error) {
	if f.isColumn() {
		return always, nil
	}
	if f.ref == nil {
		return jsonpath(f.path.present()), nil
	}
	return f.leaf(filter.OpPresent, nil)
}

func (f field) match(op filter.Operator, value any) (Clause, error) {
	if f.ref == nil {
		return f.compare(op, value), nil
	}
	return f.leaf(op, value)
}

// RFC 7643 Section 2.5: an unassigned attribute is equivalent to null, so it is not equal to a value.
func (f field) unassignable(op filter.Operator) bool {
	return op == filter.OpNotEquals && !f.isColumn() && (f.ref == nil || f.attribute.Parent == nil)
}

func (f field) leaf(op filter.Operator, value any) (Clause, error) {
	leaf, err := f.ref.leaf(f.attribute.Definition, op, value)
	if err != nil || f.attribute.Parent != nil {
		return leaf, err
	}
	return f.ref.exists(leaf), nil
}

// RFC 7643 Section 2.4: an unspecified "primary" is assumed to be false.
func (f field) defaultsFalse(op filter.Operator, value any) bool {
	return f.attribute.Definition.Name == "primary" && (op == filter.OpEquals || op == filter.OpNotEquals) && value == (op == filter.OpNotEquals)
}

func (f field) compare(op filter.Operator, value any) Clause {
	if f.defaultsFalse(op, value) {
		return jsonpath(f.path.unsetOr(op, value))
	}
	path := f.path.compare(op, value)
	if _, text := value.(string); !text || !f.attribute.Definition.CaseExact {
		return jsonpath(path)
	}
	strict := predicate{"resource @@ ?::jsonpath", []any{path}}
	if !narrowing[op] {
		return strict
	}
	return and(jsonpath(path), strict)
}
