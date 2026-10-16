package query

import (
	"strings"
	"unicode/utf8"

	"github.com/supabase-community/scim-go/pkg/filter"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
)

var _ protocol.Evaluator[Clause] = evaluator{}

type evaluator struct {
	Resource
}

func (e evaluator) Compare(attribute *protocol.Attribute, op filter.Operator, value any) (Clause, error) {
	f := e.field(attribute)
	if value == nil {
		if op != filter.OpEquals && op != filter.OpNotEquals {
			return never, nil
		}
		present, err := f.present()
		if err != nil || op == filter.OpNotEquals {
			return present, err
		}
		return not(present), nil
	}
	clause, err := e.assigned(f, op, value)
	if err != nil || !f.unassignable(op) {
		return clause, err
	}
	present, err := f.present()
	if err != nil {
		return nil, err
	}
	return or(clause, not(present)), nil
}

func (e evaluator) Present(attribute *protocol.Attribute) (Clause, error) {
	return e.field(attribute).present()
}

func (e evaluator) And(l, r Clause) (Clause, error) {
	return and(l, r), nil
}

func (e evaluator) Or(l, r Clause) (Clause, error) {
	return or(l, r), nil
}

func (e evaluator) Not(operand Clause) (Clause, error) {
	return not(operand), nil
}

func (e evaluator) ValuePath(attribute *protocol.Attribute, valueFilter func() (Clause, error)) (Clause, error) {
	inner, err := valueFilter()
	if err != nil {
		return inner, err
	}
	f := e.field(attribute)
	if f.ref != nil {
		return f.ref.exists(inner), nil
	}
	path, ok := inner.(jsonpath)
	if !ok {
		return nil, scimerrors.ErrInvalidFilter(scimerrors.InvalidFilter.Description())
	}
	return jsonpath(f.path.exists(path)), nil
}

func (e evaluator) assigned(f field, op filter.Operator, value any) (Clause, error) {
	if f.isColumn() {
		if f.name == metaLocation {
			value = e.relativeLocation(value)
		}
		return f.columnMatch(op, value)
	}
	if text, ok := value.(string); ok {
		if clause, ok := e.indexed(f, op, text); ok {
			return clause, nil
		}
	}
	return f.match(op, value)
}

func (e evaluator) indexed(f field, op filter.Operator, text string) (Clause, bool) {
	sign, ranged := comparisons[op]
	if !usesLowerName(e.schemas.Base().ID, f.name, f.attribute.Definition.CaseExact) || op == filter.OpNotEquals || !ranged && op != filter.OpStartsWith {
		return nil, false
	}
	if op == filter.OpStartsWith {
		return predicate{lowerName + " >= lower(?) AND " + lowerName + " < (lower(?) || ?)", []any{text, text, string(utf8.MaxRune)}}, true
	}
	return predicate{lowerName + " IS NOT NULL AND " + lowerName + sign + "lower(?)", []any{text}}, true
}

func (e evaluator) relativeLocation(value any) string {
	text, _ := value.(string)
	id, found := strings.CutPrefix(text, e.location+"/")
	if !found {
		return ""
	}
	return id
}

func (e evaluator) field(attribute *protocol.Attribute) field {
	keys := attribute.Keys()
	f := field{attribute: attribute, path: path{"@", keys}, ref: e.lookup(attribute.Root())}
	if attribute.Parent == nil {
		f.name, f.path.root = strings.Join(keys, "."), "$"
	}
	return f
}
