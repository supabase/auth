package scim

import (
	"fmt"

	"github.com/gofrs/uuid"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/filter"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
)

type sqlEvaluator struct {
	element string
}

func (f *sqlEvaluator) Compare(attribute *core.Attribute, key string, op filter.Operator, value any) (sqlFragment, error) {
	if frag, matched, err := f.likeCompare(attribute, key, op, value); matched {
		return frag, err
	}
	if err := f.requireUUID(key, value); err != nil {
		return sqlFragment{}, err
	}
	return f.compareOperand(attribute, key, op, value)
}

func (f *sqlEvaluator) likeCompare(attribute *core.Attribute, key string, op filter.Operator, value any) (sqlFragment, bool, error) {
	if _, ok := likePatterns[op]; !ok {
		return sqlFragment{}, false, nil
	}
	frag, err := f.like(attribute, key, op, value)
	return frag, true, err
}

func (f *sqlEvaluator) compareOperand(attribute *core.Attribute, key string, op filter.Operator, value any) (sqlFragment, error) {
	column, placeholder := f.operand(attribute, key)
	if op == filter.OpNotEquals {
		return sqlFragment{sql: column + " IS DISTINCT FROM " + placeholder, args: []any{value}}, nil
	}
	symbol, ok := comparators[op]
	if !ok {
		return sqlFragment{}, scimerrors.ErrInvalidFilter(fmt.Sprintf("operator %q is not supported", op))
	}
	return sqlFragment{sql: column + " " + symbol + " " + placeholder, args: []any{value}}, nil
}

func (f *sqlEvaluator) Present(attribute *core.Attribute, key string) (sqlFragment, error) {
	column, _ := f.resolveColumn(attribute, key)
	return sqlFragment{sql: column + " IS NOT NULL"}, nil
}

func (f *sqlEvaluator) And(left, right sqlFragment) (sqlFragment, error) {
	return combine(left, right, "AND"), nil
}

func (f *sqlEvaluator) Or(left, right sqlFragment) (sqlFragment, error) {
	return combine(left, right, "OR"), nil
}

func (f *sqlEvaluator) Not(operand sqlFragment) (sqlFragment, error) {
	return sqlFragment{sql: "(" + operand.sql + ") IS NOT TRUE", args: operand.args}, nil
}

func (f *sqlEvaluator) ValuePath(attribute *core.Attribute, key string, valueFilter func() (sqlFragment, error)) (sqlFragment, error) {
	previous := f.element
	f.element = "e"
	inner, err := valueFilter()
	f.element = previous
	if err != nil {
		return sqlFragment{}, err
	}

	source := "resource->'" + attribute.Name + "'"
	sql := "EXISTS (SELECT 1 FROM jsonb_array_elements(coalesce(" + source + ", '[]'::jsonb)) AS e WHERE " + inner.sql + ")"
	return sqlFragment{sql: sql, args: inner.args}, nil
}

func (f *sqlEvaluator) columnExpr(attribute *core.Attribute, key string) (expr string, promoted, lowered, isUUID bool) {
	column, promoted := f.resolveColumn(attribute, key)
	if promoted && uuidColumns[column] {
		return column, promoted, false, true
	}
	if attribute.Type == core.TypeString && !attribute.CaseExact {
		return loweredExpr(column), promoted, true, false
	}
	return column, promoted, false, false
}

func (f *sqlEvaluator) operand(attribute *core.Attribute, key string) (string, string) {
	expr, promoted, lowered, isUUID := f.columnExpr(attribute, key)
	if isUUID {
		return expr, "?"
	}
	if lowered {
		return expr, "lower(?)"
	}
	if cast, ok := castExpr(expr, promoted, attribute.Type); ok {
		return cast, "?"
	}
	return expr, "?"
}

func (f *sqlEvaluator) like(attribute *core.Attribute, key string, op filter.Operator, value any) (sqlFragment, error) {
	if attribute.Type != core.TypeString {
		return sqlFragment{}, scimerrors.ErrInvalidFilter(fmt.Sprintf("operator %q is not supported for a %s attribute", op, attribute.Type))
	}
	text, ok := value.(string)
	if !ok {
		return sqlFragment{}, scimerrors.ErrInvalidValue("a string value is required")
	}
	arg := fmt.Sprintf(likePatterns[op], escapeLike(text))
	return f.likeFragment(attribute, key, arg), nil
}

func (f *sqlEvaluator) likeFragment(attribute *core.Attribute, key string, arg string) sqlFragment {
	expr, _, lowered, isUUID := f.columnExpr(attribute, key)
	if isUUID {
		return sqlFragment{sql: "lower(" + expr + "::text) LIKE lower(?) ESCAPE '\\'", args: []any{arg}}
	}
	if lowered {
		return sqlFragment{sql: expr + " LIKE lower(?) ESCAPE '\\'", args: []any{arg}}
	}
	return sqlFragment{sql: expr + " LIKE ? ESCAPE '\\'", args: []any{arg}}
}

func (f *sqlEvaluator) requireUUID(key string, value any) error {
	if !f.isUUIDColumn(key) {
		return nil
	}
	text, ok := value.(string)
	if !ok {
		return scimerrors.ErrInvalidValue("a string value is required")
	}
	if _, err := uuid.FromString(text); err != nil {
		return scimerrors.ErrInvalidValue("a valid uuid value is required")
	}
	return nil
}

func (f *sqlEvaluator) isUUIDColumn(key string) bool {
	if f.element != "" {
		return false
	}
	column, ok := filterColumns[key]
	return ok && uuidColumns[column]
}
